---
layout: default
title: Arquivo
description: O arquivo agora está na página inicial.
permalink: /arquivo/
---
<p>As notas estão agora na <a href="{{ '/' | relative_url }}">página principal</a>.</p>
<script>
  window.location.replace({{ '/' | relative_url | jsonify }} + window.location.search + window.location.hash);
</script>
