// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListComponentsInput {
    /// <p>Filters results based on the type of owner for the component. By default, this request returns a list of components that your account owns. To see results for other types of owners, you can specify components that Amazon manages, third party components, or components that other accounts have shared with you.</p>
    pub owner: ::std::option::Option<crate::types::Ownership>,
    /// <p>Use the following filters to streamline results:</p>
    /// <ul>
    /// <li>
    /// <p><code>description</code></p></li>
    /// <li>
    /// <p><code>name</code></p></li>
    /// <li>
    /// <p><code>platform</code></p></li>
    /// <li>
    /// <p><code>supportedOsVersion</code></p></li>
    /// <li>
    /// <p><code>type</code></p></li>
    /// <li>
    /// <p><code>version</code></p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>Returns the list of components for the specified name.</p>
    pub by_name: ::std::option::Option<bool>,
    /// <p>The maximum items to return in a request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentsInput {
    /// <p>Filters results based on the type of owner for the component. By default, this request returns a list of components that your account owns. To see results for other types of owners, you can specify components that Amazon manages, third party components, or components that other accounts have shared with you.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Ownership> {
        self.owner.as_ref()
    }
    /// <p>Use the following filters to streamline results:</p>
    /// <ul>
    /// <li>
    /// <p><code>description</code></p></li>
    /// <li>
    /// <p><code>name</code></p></li>
    /// <li>
    /// <p><code>platform</code></p></li>
    /// <li>
    /// <p><code>supportedOsVersion</code></p></li>
    /// <li>
    /// <p><code>type</code></p></li>
    /// <li>
    /// <p><code>version</code></p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>Returns the list of components for the specified name.</p>
    pub fn by_name(&self) -> ::std::option::Option<bool> {
        self.by_name
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListComponentsInput {
    /// Creates a new builder-style object to manufacture [`ListComponentsInput`](crate::operation::list_components::ListComponentsInput).
    pub fn builder() -> crate::operation::list_components::builders::ListComponentsInputBuilder {
        crate::operation::list_components::builders::ListComponentsInputBuilder::default()
    }
}

/// A builder for [`ListComponentsInput`](crate::operation::list_components::ListComponentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListComponentsInputBuilder {
    pub(crate) owner: ::std::option::Option<crate::types::Ownership>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) by_name: ::std::option::Option<bool>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListComponentsInputBuilder {
    /// <p>Filters results based on the type of owner for the component. By default, this request returns a list of components that your account owns. To see results for other types of owners, you can specify components that Amazon manages, third party components, or components that other accounts have shared with you.</p>
    pub fn owner(mut self, input: crate::types::Ownership) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters results based on the type of owner for the component. By default, this request returns a list of components that your account owns. To see results for other types of owners, you can specify components that Amazon manages, third party components, or components that other accounts have shared with you.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Ownership>) -> Self {
        self.owner = input;
        self
    }
    /// <p>Filters results based on the type of owner for the component. By default, this request returns a list of components that your account owns. To see results for other types of owners, you can specify components that Amazon manages, third party components, or components that other accounts have shared with you.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Ownership> {
        &self.owner
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>Use the following filters to streamline results:</p>
    /// <ul>
    /// <li>
    /// <p><code>description</code></p></li>
    /// <li>
    /// <p><code>name</code></p></li>
    /// <li>
    /// <p><code>platform</code></p></li>
    /// <li>
    /// <p><code>supportedOsVersion</code></p></li>
    /// <li>
    /// <p><code>type</code></p></li>
    /// <li>
    /// <p><code>version</code></p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Use the following filters to streamline results:</p>
    /// <ul>
    /// <li>
    /// <p><code>description</code></p></li>
    /// <li>
    /// <p><code>name</code></p></li>
    /// <li>
    /// <p><code>platform</code></p></li>
    /// <li>
    /// <p><code>supportedOsVersion</code></p></li>
    /// <li>
    /// <p><code>type</code></p></li>
    /// <li>
    /// <p><code>version</code></p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Use the following filters to streamline results:</p>
    /// <ul>
    /// <li>
    /// <p><code>description</code></p></li>
    /// <li>
    /// <p><code>name</code></p></li>
    /// <li>
    /// <p><code>platform</code></p></li>
    /// <li>
    /// <p><code>supportedOsVersion</code></p></li>
    /// <li>
    /// <p><code>type</code></p></li>
    /// <li>
    /// <p><code>version</code></p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>Returns the list of components for the specified name.</p>
    pub fn by_name(mut self, input: bool) -> Self {
        self.by_name = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the list of components for the specified name.</p>
    pub fn set_by_name(mut self, input: ::std::option::Option<bool>) -> Self {
        self.by_name = input;
        self
    }
    /// <p>Returns the list of components for the specified name.</p>
    pub fn get_by_name(&self) -> &::std::option::Option<bool> {
        &self.by_name
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum items to return in a request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to specify where to start paginating. This is the nextToken from a previously truncated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListComponentsInput`](crate::operation::list_components::ListComponentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_components::ListComponentsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_components::ListComponentsInput {
            owner: self.owner,
            filters: self.filters,
            by_name: self.by_name,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
