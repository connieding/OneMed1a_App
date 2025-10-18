"use client";

import { useState } from "react";
import MediaGrid from "@/components/MediaGrid";
import { getRecommendation } from "@/api/reccomendationAPI";

async function fetchRecommendations(mediaType, mediaName) {
  try {
    const recommendations = await getRecommendation(mediaType, mediaName);
    return recommendations;
  } catch (error) {
    console.error("Error fetching recommendations:", error);
    return [];
  }
}

export default function RecommndationPage() {
  const [mediaType, setMediaType] = useState("");
  const [mediaName, setMediaName] = useState("");
  const [items, setItems] = useState([]);

  function pickCover(posterPath, backdropPath, size = "w342") {
    if (posterPath != "") {
      return "${TMDB_IMG_BASE}${size}${posterPath}";
    } else if (backdropPath != "") {
      return "${TMDB_IMG_BASE}${backdropPath}";
    } else {
      return "/next.svg";
    }
  }

  const toYear = (dateStr) =>
    dateStr ? Number(String(dateStr).slice(0, 4)) : undefined;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!mediaType || !mediaName) {
      alert("Please choose values for both inputs"); // Ensure both fields are filled
    }
    const raw = await fetchRecommendations(mediaType.toUpperCase(), mediaName);
    console.log("Raw recommendations:", raw);
    const newItems = raw.map((ums) => ({
      id: ums.mediaId ?? ums.id, // prefer the media's UUID
      title: ums.title ?? "",
      coverUrl: pickCover(ums.posterUrl, ums.backdropUrl),
      year: toYear(ums.releaseDate),
      type: ums.type.toLowerCase(),
    }));
    console.log("Processed items:", newItems);
    setItems(newItems);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Find similar media to your favourites
          </h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md space-y-4">
            <label htmlFor="mediaName" className="sr-only">
              Media name
            </label>
            <input
              id="mediaName"
              name="mediaName"
              type="text"
              value={mediaName}
              onChange={(e) => setMediaName(e.target.value)}
              required
              className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              placeholder="Enter media name"
            />
            <div>
              <label htmlFor="mediaType" className="sr-only">
                Media type
              </label>
              <select
                id="mediaType"
                name="mediaType"
                value={mediaType}
                onChange={(e) => setMediaType(e.target.value)}
                required
                className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
              >
                <option value="" disabled>
                  Select media type
                </option>
                <option value="MOVIE">Movie</option>{" "}
                {/*change the values here depending on what they are*/}
                <option value="TV">TV</option>
                <option value="BOOK">Book</option>
                <option value="MUSIC">Music</option>
              </select>
            </div>
          </div>

          <div>
            <button
              type="submit"
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              Find
            </button>
          </div>

          <MediaGrid items={items} />
        </form>
      </div>
    </div>
  );
}
