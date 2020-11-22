djt_csp
=======

Add a panel to [django-debug-toolbar](https://github.com/jazzband/django-debug-toolbar) for checking some security headers.
`djt_csp` is a close copy of the [Mozilla observatory](https://observatory.mozilla.org/). 

![Screenshot](https://github.com/d9pouces/djt_csp/raw/master/djt_csp.png)

Just install `djt-csp`...
```bash
python3 -m pip install djt-csp
```
 and add "djt_csp.panel.SecurityPanel" to your settings `DEBUG_TOOLBAR_PANELS`.
```python
# django-debug-toolbar
DEBUG_TOOLBAR_PANELS = [
    "debug_toolbar.panels.versions.VersionsPanel",
    "debug_toolbar.panels.timer.TimerPanel",
    "djt_csp.panel.SecurityPanel",
    "debug_toolbar.panels.settings.SettingsPanel",
    "debug_toolbar.panels.profiling.ProfilingPanel",
    "debug_toolbar.panels.headers.HeadersPanel",
    "debug_toolbar.panels.request.RequestPanel",
    "debug_toolbar.panels.sql.SQLPanel",
    "debug_toolbar.panels.templates.TemplatesPanel",
    "debug_toolbar.panels.staticfiles.StaticFilesPanel",
    "debug_toolbar.panels.cache.CachePanel",
    "debug_toolbar.panels.signals.SignalsPanel",
    "debug_toolbar.panels.redirects.RedirectsPanel",
]

```


