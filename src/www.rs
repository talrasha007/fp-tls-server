use anyhow::Context as _;
use cap_std::fs::{Dir, OpenOptions};
use percent_encoding::percent_decode_str;
use std::{
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub fn open(path: &Path) -> anyhow::Result<Arc<Dir>> {
    let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())
        .with_context(|| format!("open www directory {}", path.display()))?;
    anyhow::ensure!(
        dir.dir_metadata()?.is_dir(),
        "www must be a directory: {}",
        path.display()
    );
    Ok(Arc::new(dir))
}

pub struct Asset {
    pub file: tokio::fs::File,
    pub size: u64,
    pub mime: &'static str,
}

fn missing() -> io::Error {
    io::ErrorKind::NotFound.into()
}

fn relative_path(url_path: &str) -> io::Result<PathBuf> {
    let mut path = PathBuf::new();
    for part in url_path
        .strip_prefix('/')
        .ok_or_else(missing)?
        .split('/')
        .filter(|s| !s.is_empty())
    {
        let name = percent_decode_str(part)
            .decode_utf8()
            .map_err(|_| missing())?;
        if name.contains(['/', '\\', '\0'])
            || !matches!(
                Path::new(name.as_ref()).components().next(),
                Some(Component::Normal(_))
            )
        {
            return Err(missing());
        }
        path.push(name.as_ref());
    }
    if url_path.ends_with('/') {
        path.push("index.html");
    }
    Ok(path)
}

pub async fn asset(root: Arc<Dir>, url_path: &str) -> io::Result<Asset> {
    let path = relative_path(url_path)?;
    tokio::task::spawn_blocking(move || {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(target_os = "linux")]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        // Resolve the path relative to this directory handle, including symlinks.
        let file = root.open_with(&path, &options)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(missing());
        }
        let mime = mime_guess::from_path(&path)
            .first_raw()
            .unwrap_or("application/octet-stream");
        Ok(Asset {
            file: tokio::fs::File::from_std(file.into_std()),
            size: metadata.len(),
            mime,
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_resolve_to_relative_files_or_directory_indexes() {
        assert_eq!(relative_path("/").unwrap(), Path::new("index.html"));
        assert_eq!(
            relative_path("/docs/").unwrap(),
            Path::new("docs/index.html")
        );
        assert_eq!(
            relative_path("/my%20page.html").unwrap(),
            Path::new("my page.html")
        );
        for path in [
            "/../outside",
            "/%2e%2e/outside",
            "/a%2fb",
            "/a%5cb",
            "/a%00b",
        ] {
            assert!(relative_path(path).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_cannot_serve_files_outside_www() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("public");
        std::fs::create_dir(&public).unwrap();
        std::fs::write(tmp.path().join("private"), b"fixture").unwrap();
        std::os::unix::fs::symlink("../private", public.join("link")).unwrap();
        assert!(asset(open(&public).unwrap(), "/link").await.is_err());
    }
}
