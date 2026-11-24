// OpenArtemis 品牌标志（鹿首圆徽，透明底 PNG）——由 className 控制尺寸，明暗主题通用。
export function ArtemisLogo({ className }: { className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src="/logo.png" alt="OpenArtemis" className={className} />
  );
}
