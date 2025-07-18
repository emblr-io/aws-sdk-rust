// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains two attributes, <code>SortBy</code> and <code>SortOrder</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Sort {
    /// <p>For <code>ListEntities</code>, supported attributes include <code>LastModifiedDate</code> (default) and <code>EntityId</code>. In addition to <code>LastModifiedDate</code> and <code>EntityId</code>, each <code>EntityType</code> might support additional fields.</p>
    /// <p>For <code>ListChangeSets</code>, supported attributes include <code>StartTime</code> and <code>EndTime</code>.</p>
    pub sort_by: ::std::option::Option<::std::string::String>,
    /// <p>The sorting order. Can be <code>ASCENDING</code> or <code>DESCENDING</code>. The default value is <code>DESCENDING</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl Sort {
    /// <p>For <code>ListEntities</code>, supported attributes include <code>LastModifiedDate</code> (default) and <code>EntityId</code>. In addition to <code>LastModifiedDate</code> and <code>EntityId</code>, each <code>EntityType</code> might support additional fields.</p>
    /// <p>For <code>ListChangeSets</code>, supported attributes include <code>StartTime</code> and <code>EndTime</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&str> {
        self.sort_by.as_deref()
    }
    /// <p>The sorting order. Can be <code>ASCENDING</code> or <code>DESCENDING</code>. The default value is <code>DESCENDING</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
}
impl Sort {
    /// Creates a new builder-style object to manufacture [`Sort`](crate::types::Sort).
    pub fn builder() -> crate::types::builders::SortBuilder {
        crate::types::builders::SortBuilder::default()
    }
}

/// A builder for [`Sort`](crate::types::Sort).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SortBuilder {
    pub(crate) sort_by: ::std::option::Option<::std::string::String>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
}
impl SortBuilder {
    /// <p>For <code>ListEntities</code>, supported attributes include <code>LastModifiedDate</code> (default) and <code>EntityId</code>. In addition to <code>LastModifiedDate</code> and <code>EntityId</code>, each <code>EntityType</code> might support additional fields.</p>
    /// <p>For <code>ListChangeSets</code>, supported attributes include <code>StartTime</code> and <code>EndTime</code>.</p>
    pub fn sort_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sort_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For <code>ListEntities</code>, supported attributes include <code>LastModifiedDate</code> (default) and <code>EntityId</code>. In addition to <code>LastModifiedDate</code> and <code>EntityId</code>, each <code>EntityType</code> might support additional fields.</p>
    /// <p>For <code>ListChangeSets</code>, supported attributes include <code>StartTime</code> and <code>EndTime</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>For <code>ListEntities</code>, supported attributes include <code>LastModifiedDate</code> (default) and <code>EntityId</code>. In addition to <code>LastModifiedDate</code> and <code>EntityId</code>, each <code>EntityType</code> might support additional fields.</p>
    /// <p>For <code>ListChangeSets</code>, supported attributes include <code>StartTime</code> and <code>EndTime</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.sort_by
    }
    /// <p>The sorting order. Can be <code>ASCENDING</code> or <code>DESCENDING</code>. The default value is <code>DESCENDING</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sorting order. Can be <code>ASCENDING</code> or <code>DESCENDING</code>. The default value is <code>DESCENDING</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sorting order. Can be <code>ASCENDING</code> or <code>DESCENDING</code>. The default value is <code>DESCENDING</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// Consumes the builder and constructs a [`Sort`](crate::types::Sort).
    pub fn build(self) -> crate::types::Sort {
        crate::types::Sort {
            sort_by: self.sort_by,
            sort_order: self.sort_order,
        }
    }
}
