import type { Metadata } from "next";
import "./globals.css";

const siteUrl = "https://mahaloz.github.io/C-BAE/";
const title = "C-BAE Results";
const description =
  "Function-name recovery accuracy, cost, runtime, and reverse-engineering evidence across the C-BAE dataset.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: title, template: "%s · C-BAE Results" },
  description,
  openGraph: {
    title,
    description,
    type: "website",
    images: [{ url: "og.png", width: 1731, height: 909 }],
  },
  twitter: {
    card: "summary_large_image",
    title,
    description,
    images: ["og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
