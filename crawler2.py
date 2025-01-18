import asyncio
import sys
import aiohttp
import mmh3
import networkx as nx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import tabulate

class AdvancedWebCrawler:
    def __init__(self, seed_urls, max_depth=3, max_pages=50):
        self.seed_urls = seed_urls
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls = set()
        self.graph = nx.DiGraph()
        self.page_data = {}

    def charikar_fingerprint(self, text, num_bits=64):
        tokens = text.split()
        v = [0] * num_bits
        
        for token in tokens:
            token_hash = mmh3.hash(token, signed=False)
            for i in range(num_bits):
                bit = (token_hash >> i) & 1
                v[i] += 1 if bit else -1
        
        return sum(1 << i for i, val in enumerate(v) if val > 0)

    def hamming_distance(self, fp1, fp2):
        return bin(fp1 ^ fp2).count('1')

    def detect_near_duplicates(self, threshold=3):
        fingerprints = {url: self.charikar_fingerprint(content) 
                        for url, content in self.page_data.items()}
        
        duplicate_groups = []
        for url, fp1 in fingerprints.items():
            group = [url]
            for other_url, fp2 in fingerprints.items():
                if url != other_url and self.hamming_distance(fp1, fp2) <= threshold:
                    group.append(other_url)
            
            if len(group) > 1:
                duplicate_groups.append(group)
        
        return duplicate_groups

    async def fetch_page(self, session, url):
        try:
            async with session.get(url, timeout=10) as response:
                return await response.text()
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return ""

    async def crawl_url(self, session, url, depth):
        if (url in self.visited_urls or 
            depth > self.max_depth or 
            len(self.visited_urls) >= self.max_pages):
            return
        
        self.visited_urls.add(url)
        
        try:
            page_content = await self.fetch_page(session, url)
            soup = BeautifulSoup(page_content, 'html.parser')
            
            title = soup.title.string if soup.title else "No Title"
            links = [urljoin(url, link.get('href')) 
                     for link in soup.find_all('a', href=True)]
            
            # Build graph for BFS ranking
            self.graph.add_node(url)
            for link in links:
                if urlparse(link).netloc == urlparse(url).netloc:
                    self.graph.add_edge(url, link)
            
            # Store page data
            self.page_data[url] = page_content
            
            # Crawl child links
            tasks = [
                asyncio.create_task(self.crawl_url(session, link, depth + 1)) 
                for link in links 
                if urlparse(link).netloc == urlparse(url).netloc
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def compute_page_rankings(self):
        # Compute multiple centrality metrics
        pagerank = nx.pagerank(self.graph)
        in_degree = nx.in_degree_centrality(self.graph)
        out_degree = nx.out_degree_centrality(self.graph)
        
        # Combine rankings
        combined_ranking = {}
        for node in self.graph.nodes():
            combined_ranking[node] = (
                pagerank.get(node, 0) * 0.5 + 
                in_degree.get(node, 0) * 0.3 + 
                out_degree.get(node, 0) * 0.2
            )
        
        return sorted(combined_ranking.items(), key=lambda x: x[1], reverse=True)

    async def crawl(self):
        # Windows async compatibility
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.crawl_url(session, url, 0) for url in self.seed_urls]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Compute rankings and detect duplicates
        rankings = self.compute_page_rankings()
        duplicates = self.detect_near_duplicates()
        
        return {
            'rankings': rankings,
            'duplicates': duplicates
        }

async def main():
    print("Advanced Web Crawler")
    seed_urls = input("Enter seed URLs (comma-separated): ").split(',')
    seed_urls = [url.strip() for url in seed_urls]
    
    max_depth = int(input("Enter max crawl depth (default 3): ") or 3)
    max_pages = int(input("Enter max pages to crawl (default 50): ") or 50)
    
    crawler = AdvancedWebCrawler(seed_urls, max_depth, max_pages)
    results = await crawler.crawl()
    
    print("\n=== Page Rankings ===")
    for url, rank in results['rankings'][:10]:
        print(f"{url}: {rank}")
    
    print("\n=== Near-Duplicate Groups ===")
    for group in results['duplicates']:
        print(group)

if __name__ == "__main__":
    asyncio.run(main())