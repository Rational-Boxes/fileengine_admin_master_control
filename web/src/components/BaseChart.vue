<!--
  Copyright (C) 2026 James Hickman
  SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script setup lang="ts">
/**
 * ECharts, tree-shaken, and themed from the SAME CSS variables as everything else.
 *
 * Why ECharts: it is the most capable of the Vue-compatible options (time axes,
 * stacking, large series without hand-rolling canvas) and it is Apache-2.0, which
 * matters in an AGPL codebase where the licence of every dependency has to be
 * defensible.
 *
 * Imported from `echarts/core` with explicit registration rather than the default
 * bundle. The convenience import pulls in every chart type and renderer — about a
 * megabyte — onto a console whose dashboards use four of them.
 *
 * THE THEME IS READ AT RUNTIME, not duplicated. ECharts cannot use `var(--fg)`:
 * it draws to canvas and needs real colours. So the tokens are resolved from the
 * live computed style, which means one definition in App.vue governs both the DOM
 * and the charts. Hardcoding a chart palette is how the two drift until a dark
 * dashboard has light-grey axis labels nobody can read.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import {
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
} from 'echarts/components'
import VChart from 'vue-echarts'

use([
  CanvasRenderer,
  BarChart,
  LineChart,
  PieChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  TitleComponent,
])

const props = withDefaults(
  defineProps<{
    /** An ECharts option object, minus anything the theme should decide. */
    option: Record<string, any>
    height?: string
  }>(),
  { height: '260px' },
)

interface Tokens {
  fg: string
  muted: string
  border: string
  card: string
  primary: string
  danger: string
  success: string
  warning: string
}

function readTokens(): Tokens {
  const s = getComputedStyle(document.documentElement)
  const v = (n: string, fallback: string) => s.getPropertyValue(n).trim() || fallback
  return {
    fg: v('--fg', '#e6e8eb'),
    muted: v('--muted', '#98a2b3'),
    border: v('--border', '#2b313b'),
    card: v('--card', '#1c212a'),
    primary: v('--primary', '#3b82f6'),
    danger: v('--danger', '#f87171'),
    success: v('--success', '#4ade80'),
    warning: v('--warning', '#fbbf24'),
  }
}

const tokens = ref<Tokens>(readTokens())

// The theme can change under a mounted chart (the toggle sets data-theme on
// <html>), so watch for it rather than reading once at mount.
let observer: MutationObserver | null = null
onMounted(() => {
  observer = new MutationObserver(() => {
    tokens.value = readTokens()
  })
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
})
onBeforeUnmount(() => observer?.disconnect())

/** The palette, in the order series are drawn.
 *
 * Severity colours are NOT taken from this list. A chart of incidents by severity
 * has to agree with the pills in the table beside it, so those views pass their
 * own colours; this is only for series that carry no meaning of their own.
 */
const palette = computed(() => [
  tokens.value.primary,
  tokens.value.success,
  tokens.value.warning,
  tokens.value.danger,
  tokens.value.muted,
])

const themed = computed(() => {
  const t = tokens.value
  const axis = {
    axisLine: { lineStyle: { color: t.border } },
    axisTick: { show: false },
    axisLabel: { color: t.muted, fontSize: 11 },
    splitLine: { lineStyle: { color: t.border, type: 'dashed' as const } },
  }
  const base = {
    color: palette.value,
    backgroundColor: 'transparent',
    textStyle: { color: t.fg, fontFamily: getComputedStyle(document.body).fontFamily },
    // Room for axis labels without a title; the card supplies the heading.
    grid: { left: 44, right: 16, top: 24, bottom: 28, containLabel: true },
    tooltip: {
      backgroundColor: t.card,
      borderColor: t.border,
      textStyle: { color: t.fg, fontSize: 12 },
    },
    legend: { textStyle: { color: t.muted }, icon: 'circle', itemHeight: 8, itemWidth: 8 },
  }
  const opt: Record<string, any> = { ...base, ...props.option }
  // Merge rather than replace, so a view can set `data`/`type` and still get the
  // themed axis furniture.
  if (props.option.xAxis) {
    opt.xAxis = Array.isArray(props.option.xAxis)
      ? props.option.xAxis.map((a: any) => ({ ...axis, ...a }))
      : { ...axis, ...props.option.xAxis }
  }
  if (props.option.yAxis) {
    opt.yAxis = Array.isArray(props.option.yAxis)
      ? props.option.yAxis.map((a: any) => ({ ...axis, ...a }))
      : { ...axis, ...props.option.yAxis }
  }
  if (props.option.tooltip) opt.tooltip = { ...base.tooltip, ...props.option.tooltip }
  if (props.option.legend) opt.legend = { ...base.legend, ...props.option.legend }
  if (props.option.grid) opt.grid = { ...base.grid, ...props.option.grid }
  return opt
})

watch(
  () => props.option,
  () => {
    /* option is a computed in every caller; this keeps the dep explicit */
  },
)
</script>

<template>
  <VChart :option="themed" :style="{ height }" autoresize />
</template>
