from typing import List, Dict, Optional
from pydantic import BaseModel, validator, root_validator
from datetime import datetime
import requests


class ItemModel(BaseModel):
    cve: Dict
    configurations: Optional[Dict]
    impact: Optional[Dict]
    publishedDate: datetime
    lastModifiedDate: datetime


class ResultModel(BaseModel):
    CVE_data_timestamp: datetime
    CVE_data_type: str
    CVE_Items: List[ItemModel]

    @validator('CVE_data_type')
    def fixed_type(cls, v):
        assert v == 'CVE', 'Must be of type CVE'
        return v


class ResponseModel(BaseModel):
    resultsPerPage: int
    startIndex: int
    totalResults: int
    result: ResultModel


class NVD:
    def __init__(self, params, base_url='https://services.nvd.nist.gov/rest/json/cves/1.0'):
        self.base_url = base_url
        self.params = params
        self._session = None
        self._total_results = None
        self.results = []

    @property
    def cves(self):
        while self._total_results > len(self.results):
            self._get(offset=len(self.results))
        return self.results

    def _get(self, offset=0):
        self.params['startIndex'] = offset
        response = self._session.get(self.base_url, params=self.params).json()
        format_results = ResponseModel(**response)
        self._total_results = format_results.totalResults
        self.results += format_results.dict()['result']['CVE_Items']

    def __enter__(self):
        self._session = requests.Session()
        self._get(offset=0)
        return self

    def __exit__(self, *args, **kwargs):
        self._session.close()