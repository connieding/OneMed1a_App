import axios from "axios";

// This is the apiClient and is used to defined where the backend is hosted
const apiClient = axios.create({
  baseURL: "http://localhost:8080",
  withCredentials: true,
});

export default apiClient;
