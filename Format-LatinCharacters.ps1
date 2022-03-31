function Format-LatinCharacters {
    param(
        [string]$String
    )

    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))

}