const revealTargets = [
  ".hero-copy",
  ".hero-card",
  ".section-title",
  ".section-subtitle",
  ".card",
  ".cta-inner",
  ".faq-item",
  ".tech-grid",
  ".newsletter-inner",
];

function initRevealAnimations() {
  const elements = document.querySelectorAll(revealTargets.join(","));
  if (!elements.length) return;

  elements.forEach((el) => el.classList.add("reveal"));

  if (!("IntersectionObserver" in window)) {
    elements.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries, obs) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          obs.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.2 }
  );

  elements.forEach((el) => observer.observe(el));
}

document.addEventListener("DOMContentLoaded", initRevealAnimations);
