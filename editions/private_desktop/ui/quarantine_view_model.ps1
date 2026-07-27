function Get-AIShieldQuarantineOperation {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Source
    )

    $normalized = $Source.Replace('/', '\')
    if ($normalized -match '(?i)\\codex-runtimes\\(?<source>codex-runtime-install-[^\\]+)(?:\\|$)') {
        $operationSource = [string]$Matches.source
        return [pscustomobject]@{
            Key = "operation:codex-runtime:$($operationSource.ToLowerInvariant())"
            Title = "Codex Runtime Installation"
            Source = $operationSource
        }
    }

    if ($normalized -match '(?i)\\(?<source>[a-z0-9][a-z0-9._-]*(?:install|setup|update)[a-z0-9._-]*)(?:\\|$)') {
        $operationSource = [string]$Matches.source
        return [pscustomobject]@{
            Key = "operation:installer:$($operationSource.ToLowerInvariant())"
            Title = "Installationsvorgang"
            Source = $operationSource
        }
    }

    return [pscustomobject]@{
        Key = "other:individual"
        Title = "Einzelne Downloads und Dateien"
        Source = "Verschiedene Quellen"
    }
}

function ConvertTo-AIShieldQuarantineViewItems {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [object[]]$Items = @()
    )

    $rows = [Collections.Generic.List[object]]::new()
    foreach ($item in @($Items)) {
        if ($null -eq $item) { continue }
        $source = [string]$item.Source
        $operation = Get-AIShieldQuarantineOperation -Source $source
        $name = [IO.Path]::GetFileName($source.TrimEnd('\', '/'))
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$item.Id }
        $state = [string]$item.State
        $stateDisplay = switch ($state) {
            "committed" { "Gesichert" }
            "released" { "Freigegeben" }
            default { $state }
        }
        $rows.Add([pscustomobject]@{
            Id = [string]$item.Id
            Name = $name
            Source = $source
            Size = [string]$item.Size
            State = $state
            StateDisplay = $stateDisplay
            Classification = [string]$item.Classification
            GroupKey = [string]$operation.Key
            GroupTitle = [string]$operation.Title
            GroupSource = [string]$operation.Source
            GroupCount = 0
            GroupStatus = ""
        })
    }

    foreach ($group in @($rows | Group-Object GroupKey)) {
        $committed = @($group.Group | Where-Object State -eq "committed").Count
        $released = @($group.Group | Where-Object State -eq "released").Count
        $status = if ($committed -gt 0 -and $released -gt 0) {
            "Teilweise freigegeben"
        } elseif ($committed -gt 0) {
            "Prüfung/Freigabe erforderlich"
        } else {
            "Freigegeben"
        }
        foreach ($row in $group.Group) {
            $row.GroupCount = $group.Count
            $row.GroupStatus = $status
        }
    }

    return @($rows)
}
