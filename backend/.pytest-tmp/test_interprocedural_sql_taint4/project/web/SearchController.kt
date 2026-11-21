class SearchController(private val service: SearchService) {
    fun search(@RequestParam term: String) = service.find(term)
}
