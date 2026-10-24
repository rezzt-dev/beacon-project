"""application services: the business rules shared by the cli and the live api.

every function takes a `Repository` (one per thread) and returns plain data, so the cli renders it
with rich and the api serializes it as json without a second implementation of any rule.
"""
