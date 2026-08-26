<script lang="ts" generics="Item extends { sub: string }">
  import type { Snippet } from 'svelte'

  let {
    items,
    rowHeight = 30,
    overscan = 10,
    epoch = 0,
    row,
  }: {
    items: Item[]
    rowHeight?: number
    overscan?: number
    /** Bump to snap back to the top (new search); filtering does not. */
    epoch?: number
    row: Snippet<[Item, number]>
  } = $props()

  let viewport: HTMLDivElement | undefined = $state()
  let scrollTop = $state(0)
  let viewH = $state(480)

  const start = $derived(Math.max(0, Math.floor(scrollTop / rowHeight) - overscan))
  const end = $derived(Math.min(items.length, Math.ceil((scrollTop + viewH) / rowHeight) + overscan))
  const slice = $derived(items.slice(start, end))

  function onScroll() {
    if (viewport) scrollTop = viewport.scrollTop
  }

  function measure() {
    if (!viewport) return
    // Safety cap: if a layout accident ever makes the viewport report an
    // absurd height, virtualizing more rows than any screen could show
    // would be catastrophic. 20k px is far beyond any real viewport.
    viewH = Math.min(viewport.clientHeight, 20000)
  }

  $effect(() => {
    measure()
    if (!viewport) return
    const ro = new ResizeObserver(measure)
    ro.observe(viewport)
    return () => ro.disconnect()
  })

  $effect(() => {
    void epoch
    if (viewport) {
      viewport.scrollTop = 0
      scrollTop = 0
    }
  })
</script>

<div class="viewport" bind:this={viewport} onscroll={onScroll}>
  <div class="spacer" style="height: {items.length * rowHeight}px">
    <div class="offset" style="transform: translateY({start * rowHeight}px)">
      {#each slice as item, i (start + i)}
        {@render row(item, start + i)}
      {/each}
    </div>
  </div>
</div>

<style>
  .viewport {
    height: 100%;
    overflow-y: auto;
    overscroll-behavior: contain;
  }

  .spacer {
    position: relative;
  }

  .offset {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
  }
</style>
