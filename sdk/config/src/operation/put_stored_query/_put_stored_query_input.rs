// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutStoredQueryInput {
    /// <p>A list of <code>StoredQuery</code> objects. The mandatory fields are <code>QueryName</code> and <code>Expression</code>.</p><note>
    /// <p>When you are creating a query, you must provide a query name and an expression. When you are updating a query, you must provide a query name but updating the description is optional.</p>
    /// </note>
    pub stored_query: ::std::option::Option<crate::types::StoredQuery>,
    /// <p>A list of <code>Tags</code> object.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutStoredQueryInput {
    /// <p>A list of <code>StoredQuery</code> objects. The mandatory fields are <code>QueryName</code> and <code>Expression</code>.</p><note>
    /// <p>When you are creating a query, you must provide a query name and an expression. When you are updating a query, you must provide a query name but updating the description is optional.</p>
    /// </note>
    pub fn stored_query(&self) -> ::std::option::Option<&crate::types::StoredQuery> {
        self.stored_query.as_ref()
    }
    /// <p>A list of <code>Tags</code> object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl PutStoredQueryInput {
    /// Creates a new builder-style object to manufacture [`PutStoredQueryInput`](crate::operation::put_stored_query::PutStoredQueryInput).
    pub fn builder() -> crate::operation::put_stored_query::builders::PutStoredQueryInputBuilder {
        crate::operation::put_stored_query::builders::PutStoredQueryInputBuilder::default()
    }
}

/// A builder for [`PutStoredQueryInput`](crate::operation::put_stored_query::PutStoredQueryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutStoredQueryInputBuilder {
    pub(crate) stored_query: ::std::option::Option<crate::types::StoredQuery>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PutStoredQueryInputBuilder {
    /// <p>A list of <code>StoredQuery</code> objects. The mandatory fields are <code>QueryName</code> and <code>Expression</code>.</p><note>
    /// <p>When you are creating a query, you must provide a query name and an expression. When you are updating a query, you must provide a query name but updating the description is optional.</p>
    /// </note>
    /// This field is required.
    pub fn stored_query(mut self, input: crate::types::StoredQuery) -> Self {
        self.stored_query = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of <code>StoredQuery</code> objects. The mandatory fields are <code>QueryName</code> and <code>Expression</code>.</p><note>
    /// <p>When you are creating a query, you must provide a query name and an expression. When you are updating a query, you must provide a query name but updating the description is optional.</p>
    /// </note>
    pub fn set_stored_query(mut self, input: ::std::option::Option<crate::types::StoredQuery>) -> Self {
        self.stored_query = input;
        self
    }
    /// <p>A list of <code>StoredQuery</code> objects. The mandatory fields are <code>QueryName</code> and <code>Expression</code>.</p><note>
    /// <p>When you are creating a query, you must provide a query name and an expression. When you are updating a query, you must provide a query name but updating the description is optional.</p>
    /// </note>
    pub fn get_stored_query(&self) -> &::std::option::Option<crate::types::StoredQuery> {
        &self.stored_query
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of <code>Tags</code> object.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>Tags</code> object.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of <code>Tags</code> object.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`PutStoredQueryInput`](crate::operation::put_stored_query::PutStoredQueryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_stored_query::PutStoredQueryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_stored_query::PutStoredQueryInput {
            stored_query: self.stored_query,
            tags: self.tags,
        })
    }
}
