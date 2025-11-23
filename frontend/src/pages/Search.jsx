import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";

function useQuery() {
  return new URLSearchParams(useLocation().search);
}

export default function Search() {
  const q = useQuery().get("q") || "";
  const [query, setQuery] = useState(q);

  // When loaded with ?q=... we prefill the field
  useEffect(() => {
    setQuery(q);
  }, [q]);

  // Backend search endpoint
  const backendSearch = "/api/search";

  // Minimal, intentionally 'glitchy' UI: plain HTML-like appearance
  return (
    <div
      style={{
        padding: 20,
        fontFamily: "monospace",
        background: "#f4f4f4",
        minHeight: "100vh",
      }}
    >
      <h1 style={{ fontSize: 18, marginBottom: 8 }}>Search</h1>
      <form method="GET" action={backendSearch}>
        <input
          name="q"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search offers"
          style={{ width: "60%", padding: 6, fontFamily: "monospace" }}
        />
        <button type="submit" style={{ marginLeft: 8, padding: "6px 10px" }}>
          Go
        </button>
      </form>
      <p style={{ marginTop: 12, color: "#666" }}>
        {query ? `query: ${query}` : ""}
      </p>
    </div>
  );
}
