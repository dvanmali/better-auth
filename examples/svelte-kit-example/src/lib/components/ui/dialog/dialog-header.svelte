<script lang="ts">
import { cn } from "$lib/utils";
import type { HTMLAttributes } from "svelte/elements";

type $$Props = HTMLAttributes<HTMLDivElement>;

let className: $$Props["class"] = undefined;
export { className as class };
</script>

<div class={cn("flex flex-col space-y-1.5 text-center sm:text-left", className)} {...$$restProps}>
	<slot />
</div>
