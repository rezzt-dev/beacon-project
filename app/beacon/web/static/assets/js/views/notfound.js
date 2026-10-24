import { emptyState } from "../components.js";
import { h, replace } from "../dom.js";
import { t } from "../i18n.js";

export async function mount(root) {
  replace(root, h("h1", {}, t("notfound.title")), emptyState(t("notfound.text"), null, { label: t("nav.overview"), href: "/" }));
  return {};
}
