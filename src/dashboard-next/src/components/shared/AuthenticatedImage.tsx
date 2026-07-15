import { useEffect, useRef, useState, type ImgHTMLAttributes } from 'react';
import { fetchAuthenticatedBlobUrl } from '../../lib/dashboard-transport';

interface AuthenticatedImageProps extends Omit<ImgHTMLAttributes<HTMLImageElement>, 'src'> {
  src: string;
  linkToFullSize?: boolean;
}

/** Load a protected image through the shared Bearer transport. */
export function AuthenticatedImage({ src, linkToFullSize = false, ...props }: AuthenticatedImageProps) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [shouldLoad, setShouldLoad] = useState(props.loading !== 'lazy');
  const placeholderRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (props.loading !== 'lazy' || typeof IntersectionObserver === 'undefined') {
      setShouldLoad(true);
      return;
    }
    setShouldLoad(false);
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) {
        setShouldLoad(true);
        observer.disconnect();
      }
    }, { rootMargin: '200px' });
    if (placeholderRef.current) observer.observe(placeholderRef.current);
    return () => observer.disconnect();
  }, [src, props.loading]);

  useEffect(() => {
    if (!shouldLoad) return;
    const controller = new AbortController();
    let revoke: (() => void) | undefined;
    setBlobUrl(null);
    fetchAuthenticatedBlobUrl(src, controller.signal)
      .then(resource => {
        if (controller.signal.aborted) {
          resource.revoke();
          return;
        }
        revoke = resource.revoke;
        setBlobUrl(resource.url);
      })
      .catch(() => {
        if (!controller.signal.aborted) setBlobUrl(null);
      });
    return () => {
      controller.abort();
      revoke?.();
    };
  }, [src, shouldLoad]);

  if (!blobUrl) {
    return (
      <span
        ref={placeholderRef}
        aria-hidden="true"
        className={props.className}
        style={{ display: 'inline-block', minHeight: 1, ...props.style }}
      />
    );
  }
  const image = <img src={blobUrl} {...props} />;
  return linkToFullSize
    ? <a href={blobUrl} target="_blank" rel="noreferrer" className="block">{image}</a>
    : image;
}
