# -*- coding: utf-8 -*-
import json
import re
import sys
from base.spider import Spider
from pyquery import PyQuery as pq

class Spider(Spider):
    def init(self, extend=""):
        self.host = "https://missav.ws"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': f'{self.host}/',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }

    def getName(self):
        return "MissAV"

    def isVideoFormat(self, url):
        return url.lower().endswith('.m3u8') or url.lower().endswith('.mp4')

    def manualVideoCheck(self):
        return True

    def destroy(self):
        pass

    def homeContent(self, filter):
        result = {}
        classes = []
        cateManual = {
            "最新视频": "new",
            "中文自幕": "chinese-subtitle",
            "国产无码": "uncensored-leak",
            "VR视频": "vr",
            "独立制片": "individual",
            "本月热榜": "monthly-hot"
        }
        for k, v in cateManual.items():
            classes.append({'type_name': k, 'type_id': v})
        result['class'] = classes
        result['filters'] = {}
        return result

    def homeVideoContent(self):
        try:
            url = f'{self.host}/cn/new'
            res = self.fetch(url, headers=self.headers)
            return {'list': self.parse_list(res.text)}
        except Exception:
            return {'list': []}

    def categoryContent(self, tid, pg, filter, extend):
        result = {}
        if tid == "new":
            url = f'{self.host}/cn/new?page={pg}'
        else:
            url = f'{self.host}/cn/{tid}?page={pg}'
        try:
            res = self.fetch(url, headers=self.headers)
            result['list'] = self.parse_list(res.text)
            result['page'] = int(pg)
            result['pagecount'] = 999
            result['limit'] = 20
            result['total'] = 9999
        except Exception:
            result['list'] = []
        return result

    def detailContent(self, ids):
        tid = ids[0]
        url = tid if tid.startswith('http') else (f'{self.host}{tid}' if tid.startswith('/') else f'{self.host}/cn/{tid}')
        res = self.fetch(url, headers=self.headers)
        content = res.text
        title = ""
        pic = ""
        
        title_match = re.search(r'<meta property="og:title" content="(.*?)">', content)
        if title_match:
            title = title_match.group(1).split(' | ')[0]
        else:
            d = pq(content)
            title = d('h1').text() or d('title').text()
        
        pic_match = re.search(r'<meta property="og:image" content="(.*?)">', content)
        if pic_match:
            pic = pic_match.group(1)

        vod_play_from_list = []
        vod_play_url_list = []
        
        pat = r'(https?://[^\s"\']+\.m3u8[^\s"\']*)'
        matches = re.findall(pat, content)
        
        if not matches:
            pat_fallback = r'source\s*:\s*["\']([^"\']+\.m3u8[^"\']*)["\']'
            matches = re.findall(pat_fallback, content)

        unique_urls = []
        seen = set()
        for m in matches:
            full_url = m if m.startswith('http') else f"{self.host}{m}"
            if full_url not in seen:
                seen.add(full_url)
                unique_urls.append(full_url)

        for index, u in enumerate(unique_urls):
            vod_play_from_list.append(f"拦截线路 {index + 1}")
            vod_play_url_list.append(u)

        if not unique_urls:
            vod_play_from_list.append("WebHome内置流")
            vod_play_url_list.append(url)

        vod = {
            'vod_id': tid,
            'vod_name': title.strip() if title else "MissAV 视频",
            'vod_pic': pic,
            'type_name': '',
            'vod_year': '',
            'vod_area': '',
            'vod_remarks': '',
            'vod_actor': '',
            'vod_director': '',
            'vod_content': '',
            'vod_play_from': '$$$'.join(vod_play_from_list),
            'vod_play_url': '$$$'.join(vod_play_url_list)
        }
        return {'list': [vod]}

    def searchContent(self, key, quick, pg="1"):
        url = f'{self.host}/cn/search/{key}?page={pg}'
        try:
            res = self.fetch(url, headers=self.headers)
            return {'list': self.parse_list(res.text)}
        except:
            return {'list': []}

    def playerContent(self, flag, id, vipFlags):
        return {
            'parse': 0,
            'url': id,
            'header': {
                'User-Agent': self.headers['User-Agent'],
                'Referer': f'{self.host}/'
            }
        }

    def localProxy(self, param):
        pass

    def parse_list(self, html):
        videos = []
        d = pq(html)
        
        # 核心修复：只寻找包含图片并且拥有 data-src 懒加载属性的卡片容器
        items = d('a[href*="/cn/"]')
        seen_ids = set()
        
        # 黑名单列表：只要链接包含这些词，一律是菜单按钮，直接扔掉
        blacklist = [
            '/vip', '/chinese-subtitle', '/uncensored-leak', '/vr', 
            '/individual', '/today-hot', '/actresses', '/makers', 
            '/tags', '/genres', '/search', '/new', '/teachers', '/series', '/release'
        ]
        
        for item in items.items():
            href = item.attr('href')
            if not href or href in seen_ids:
                continue
                
            # 1. 拦截黑名单菜单链接
            if any(b_word in href for b_word in blacklist):
                continue
                
            img_tag = item.find('img')
            pic = img_tag.attr('data-src') or img_tag.attr('src') or ""
            
            # 2. 关键防御：如果这个 a 标签里面根本连图片都没有，绝对不是视频卡片，直接过滤
            if not pic:
                continue
                
            title = item.attr('title') or img_tag.attr('alt') or item.find('.title').text()
            if not title:
                title = item.text().strip()
                
            # 过滤掉标题过短的无效节点
            if not title or len(title) <= 3:
                continue
                
            remarks = item.find('.duration, .time, span').text()
            
            seen_ids.add(href)
            videos.append({
                'vod_id': href,
                'vod_name': title.strip(),
                'vod_pic': pic,
                'vod_remarks': remarks.strip() if remarks else ""
            })
        return videos
