// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about how a custom index field is used during a search.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Search {
    /// <p>Indicates that the field can be used to create search facets, a count of results for each value in the field. The default is <code>false</code> .</p>
    pub facetable: bool,
    /// <p>Determines whether the field is used in the search. If the <code>Searchable</code> field is <code>true</code>, you can use relevance tuning to manually tune how Amazon Kendra weights the field in the search. The default is <code>true</code> for string fields and <code>false</code> for number and date fields.</p>
    pub searchable: bool,
    /// <p>Determines whether the field is returned in the query response. The default is <code>true</code>.</p>
    pub displayable: bool,
    /// <p>Determines whether the field can be used to sort the results of a query. If you specify sorting on a field that does not have <code>Sortable</code> set to <code>true</code>, Amazon Kendra returns an exception. The default is <code>false</code>.</p>
    pub sortable: bool,
}
impl Search {
    /// <p>Indicates that the field can be used to create search facets, a count of results for each value in the field. The default is <code>false</code> .</p>
    pub fn facetable(&self) -> bool {
        self.facetable
    }
    /// <p>Determines whether the field is used in the search. If the <code>Searchable</code> field is <code>true</code>, you can use relevance tuning to manually tune how Amazon Kendra weights the field in the search. The default is <code>true</code> for string fields and <code>false</code> for number and date fields.</p>
    pub fn searchable(&self) -> bool {
        self.searchable
    }
    /// <p>Determines whether the field is returned in the query response. The default is <code>true</code>.</p>
    pub fn displayable(&self) -> bool {
        self.displayable
    }
    /// <p>Determines whether the field can be used to sort the results of a query. If you specify sorting on a field that does not have <code>Sortable</code> set to <code>true</code>, Amazon Kendra returns an exception. The default is <code>false</code>.</p>
    pub fn sortable(&self) -> bool {
        self.sortable
    }
}
impl Search {
    /// Creates a new builder-style object to manufacture [`Search`](crate::types::Search).
    pub fn builder() -> crate::types::builders::SearchBuilder {
        crate::types::builders::SearchBuilder::default()
    }
}

/// A builder for [`Search`](crate::types::Search).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchBuilder {
    pub(crate) facetable: ::std::option::Option<bool>,
    pub(crate) searchable: ::std::option::Option<bool>,
    pub(crate) displayable: ::std::option::Option<bool>,
    pub(crate) sortable: ::std::option::Option<bool>,
}
impl SearchBuilder {
    /// <p>Indicates that the field can be used to create search facets, a count of results for each value in the field. The default is <code>false</code> .</p>
    pub fn facetable(mut self, input: bool) -> Self {
        self.facetable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates that the field can be used to create search facets, a count of results for each value in the field. The default is <code>false</code> .</p>
    pub fn set_facetable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.facetable = input;
        self
    }
    /// <p>Indicates that the field can be used to create search facets, a count of results for each value in the field. The default is <code>false</code> .</p>
    pub fn get_facetable(&self) -> &::std::option::Option<bool> {
        &self.facetable
    }
    /// <p>Determines whether the field is used in the search. If the <code>Searchable</code> field is <code>true</code>, you can use relevance tuning to manually tune how Amazon Kendra weights the field in the search. The default is <code>true</code> for string fields and <code>false</code> for number and date fields.</p>
    pub fn searchable(mut self, input: bool) -> Self {
        self.searchable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the field is used in the search. If the <code>Searchable</code> field is <code>true</code>, you can use relevance tuning to manually tune how Amazon Kendra weights the field in the search. The default is <code>true</code> for string fields and <code>false</code> for number and date fields.</p>
    pub fn set_searchable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.searchable = input;
        self
    }
    /// <p>Determines whether the field is used in the search. If the <code>Searchable</code> field is <code>true</code>, you can use relevance tuning to manually tune how Amazon Kendra weights the field in the search. The default is <code>true</code> for string fields and <code>false</code> for number and date fields.</p>
    pub fn get_searchable(&self) -> &::std::option::Option<bool> {
        &self.searchable
    }
    /// <p>Determines whether the field is returned in the query response. The default is <code>true</code>.</p>
    pub fn displayable(mut self, input: bool) -> Self {
        self.displayable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the field is returned in the query response. The default is <code>true</code>.</p>
    pub fn set_displayable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.displayable = input;
        self
    }
    /// <p>Determines whether the field is returned in the query response. The default is <code>true</code>.</p>
    pub fn get_displayable(&self) -> &::std::option::Option<bool> {
        &self.displayable
    }
    /// <p>Determines whether the field can be used to sort the results of a query. If you specify sorting on a field that does not have <code>Sortable</code> set to <code>true</code>, Amazon Kendra returns an exception. The default is <code>false</code>.</p>
    pub fn sortable(mut self, input: bool) -> Self {
        self.sortable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the field can be used to sort the results of a query. If you specify sorting on a field that does not have <code>Sortable</code> set to <code>true</code>, Amazon Kendra returns an exception. The default is <code>false</code>.</p>
    pub fn set_sortable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.sortable = input;
        self
    }
    /// <p>Determines whether the field can be used to sort the results of a query. If you specify sorting on a field that does not have <code>Sortable</code> set to <code>true</code>, Amazon Kendra returns an exception. The default is <code>false</code>.</p>
    pub fn get_sortable(&self) -> &::std::option::Option<bool> {
        &self.sortable
    }
    /// Consumes the builder and constructs a [`Search`](crate::types::Search).
    pub fn build(self) -> crate::types::Search {
        crate::types::Search {
            facetable: self.facetable.unwrap_or_default(),
            searchable: self.searchable.unwrap_or_default(),
            displayable: self.displayable.unwrap_or_default(),
            sortable: self.sortable.unwrap_or_default(),
        }
    }
}
