function Format-LatinCharacters {
    param(
        [Parameter(ValueFromPipeline)]
        [string]$String
    )

    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))

}