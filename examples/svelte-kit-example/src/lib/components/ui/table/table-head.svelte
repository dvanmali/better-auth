<script lang="ts">
import { cn } from "$lib/utils";
import type { HTMLThAttributes } from "svelte/elements";

type $$Props = HTMLThAttributes;

let className: $$Props["class"] = undefined;
export { className as class };
</script>

<th
	class={cn(
		"text-muted-foreground h-10 px-2 text-left align-middle font-medium [&:has([role=checkbox])]:pr-0 [&>[role=checkbox]]:translate-y-[2px]",
		className
	)}
	{...$$restProps}
>
	<slot />
</th>
