<script lang="ts">
import { Calendar as CalendarPrimitive } from "bits-ui";
import { cn } from "$lib/utils.js";
import { buttonVariants } from "../button";
import ChevronRight from "svelte-radix/ChevronRight.svelte";

type $$Props = CalendarPrimitive.NextButtonProps;
type $$Events = CalendarPrimitive.NextButtonEvents;

let className: $$Props["class"] = undefined;
export { className as class };
</script>

<CalendarPrimitive.NextButton
	on:click
	class={cn(
		buttonVariants({ variant: "outline" }),
		"h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100",
		className
	)}
	{...$$restProps}
	let:builder
>
	<slot {builder}>
		<ChevronRight class="h-4 w-4" />
	</slot>
</CalendarPrimitive.NextButton>
