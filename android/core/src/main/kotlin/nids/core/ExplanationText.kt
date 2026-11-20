package nids.core

/** Remove presentation boilerplate only; factual acceptance remains separate. */
object ExplanationText{
    fun notificationDraft(value: String): String{
        var text=value.replace(Regex("<\\|[^>]+\\|>"),"").trim()
        val paragraph=text.indexOf("\n\n")
        val first=if(paragraph>=0)text.substring(0,paragraph).lowercase() else ""
        if(paragraph in 1..300 && (first.startsWith("here is") || first.startsWith("here's") || first.startsWith("certainly") || first.startsWith("sure"))){
            text=text.substring(paragraph+2).trim()
        }
        return text.lines().map{it.trim().removePrefix("- ").removePrefix("* ")}
            .filter{it.isNotEmpty()}.distinct().joinToString(" ").replace(Regex("\\s+")," ").trim()
    }
}
