<script lang="ts">
import { cn } from "$lib/utils";
import type { HTMLAttributes } from "svelte/elements";

type $$Props = HTMLAttributes<HTMLTableCaptionElement>;

let className: $$Props["class"] = undefined;
export { className as class };
</script>

<caption class={cn("text-muted-foreground mt-4 text-sm", className)} {...$$restProps}>
	<slot />
</caption>
