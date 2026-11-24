// Artemis brand logo (fox with curled tail round emblem, transparent-background PNG): size controlled by className, works in both light and dark themes.
export function ArtemisLogo({ className }: { className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src="/logo.png" alt="Artemis" className={className} />
  );
}
