<script lang="ts">
import { cn } from "$lib/utils";
import { Accordion as AccordionPrimitive } from "bits-ui";

type $$Props = AccordionPrimitive.ItemProps;

let className: $$Props["class"] = undefined;
export { className as class };
export let value: $$Props["value"];
</script>

<AccordionPrimitive.Item {value} class={cn("border-b", className)} {...$$restProps}>
	<slot />
</AccordionPrimitive.Item>
