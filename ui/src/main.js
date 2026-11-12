import { mount } from "svelte";
import "./style.css";
import App from "./App.svelte";

const desktop = "__TAURI_INTERNALS__" in window || "__TAURI__" in window;
document.documentElement.classList.add(desktop ? "desktop" : "web");

mount(App, { target: document.getElementById("app") });
