<script lang="ts">
import { cn } from "$lib/utils";
import { Calendar as CalendarPrimitive } from "bits-ui";

type $$Props = CalendarPrimitive.GridProps;

let className: $$Props["class"] = undefined;
export { className as class };
</script>

<CalendarPrimitive.Grid class={cn("w-full border-collapse space-y-1", className)} {...$$restProps}>
	<slot />
</CalendarPrimitive.Grid>
