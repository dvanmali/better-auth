<script lang="ts">
import { cn } from "$lib/utils";
import { DropdownMenu as DropdownMenuPrimitive } from "bits-ui";

type $$Props = DropdownMenuPrimitive.LabelProps & {
	inset?: boolean;
};

let className: $$Props["class"] = undefined;
export let inset: $$Props["inset"] = undefined;
export { className as class };
</script>

<DropdownMenuPrimitive.Label
	class={cn("px-2 py-1.5 text-sm font-semibold", inset && "pl-8", className)}
	{...$$restProps}
>
	<slot />
</DropdownMenuPrimitive.Label>
