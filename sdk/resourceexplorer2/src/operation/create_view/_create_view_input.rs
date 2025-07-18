// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateViewInput {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your views.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the new view. This name appears in the list of views in Resource Explorer.</p>
    /// <p>The name must be no more than 64 characters long, and can include letters, digits, and the dash (-) character. The name must be unique within its Amazon Web Services Region.</p>
    pub view_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies optional fields that you want included in search results from this view. It is a list of objects that each describe a field to include.</p>
    /// <p>The default is an empty list, with no optional fields included in the results.</p>
    pub included_properties: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>,
    /// <p>The root ARN of the account, an organizational unit (OU), or an organization ARN. If left empty, the default is account.</p>
    pub scope: ::std::option::Option<::std::string::String>,
    /// <p>An array of strings that specify which resources are included in the results of queries made using this view. When you use this view in a <code>Search</code> operation, the filter string is combined with the search's <code>QueryString</code> parameter using a logical <code>AND</code> operator.</p>
    /// <p>For information about the supported syntax, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query reference for Resource Explorer</a> in the <i>Amazon Web Services Resource Explorer User Guide</i>.</p><important>
    /// <p>This query string in the context of this operation supports only <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-filters">filter prefixes</a> with optional <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-operators">operators</a>. It doesn't support free-form text. For example, the string <code>region:us* service:ec2 -tag:stage=prod</code> includes all Amazon EC2 resources in any Amazon Web Services Region that begins with the letters <code>us</code> and is <i>not</i> tagged with a key <code>Stage</code> that has the value <code>prod</code>.</p>
    /// </important>
    pub filters: ::std::option::Option<crate::types::SearchFilter>,
    /// <p>Tag key and value pairs that are attached to the view.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateViewInput {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your views.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The name of the new view. This name appears in the list of views in Resource Explorer.</p>
    /// <p>The name must be no more than 64 characters long, and can include letters, digits, and the dash (-) character. The name must be unique within its Amazon Web Services Region.</p>
    pub fn view_name(&self) -> ::std::option::Option<&str> {
        self.view_name.as_deref()
    }
    /// <p>Specifies optional fields that you want included in search results from this view. It is a list of objects that each describe a field to include.</p>
    /// <p>The default is an empty list, with no optional fields included in the results.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.included_properties.is_none()`.
    pub fn included_properties(&self) -> &[crate::types::IncludedProperty] {
        self.included_properties.as_deref().unwrap_or_default()
    }
    /// <p>The root ARN of the account, an organizational unit (OU), or an organization ARN. If left empty, the default is account.</p>
    pub fn scope(&self) -> ::std::option::Option<&str> {
        self.scope.as_deref()
    }
    /// <p>An array of strings that specify which resources are included in the results of queries made using this view. When you use this view in a <code>Search</code> operation, the filter string is combined with the search's <code>QueryString</code> parameter using a logical <code>AND</code> operator.</p>
    /// <p>For information about the supported syntax, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query reference for Resource Explorer</a> in the <i>Amazon Web Services Resource Explorer User Guide</i>.</p><important>
    /// <p>This query string in the context of this operation supports only <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-filters">filter prefixes</a> with optional <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-operators">operators</a>. It doesn't support free-form text. For example, the string <code>region:us* service:ec2 -tag:stage=prod</code> includes all Amazon EC2 resources in any Amazon Web Services Region that begins with the letters <code>us</code> and is <i>not</i> tagged with a key <code>Stage</code> that has the value <code>prod</code>.</p>
    /// </important>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::SearchFilter> {
        self.filters.as_ref()
    }
    /// <p>Tag key and value pairs that are attached to the view.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for CreateViewInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateViewInput");
        formatter.field("client_token", &self.client_token);
        formatter.field("view_name", &self.view_name);
        formatter.field("included_properties", &self.included_properties);
        formatter.field("scope", &self.scope);
        formatter.field("filters", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateViewInput {
    /// Creates a new builder-style object to manufacture [`CreateViewInput`](crate::operation::create_view::CreateViewInput).
    pub fn builder() -> crate::operation::create_view::builders::CreateViewInputBuilder {
        crate::operation::create_view::builders::CreateViewInputBuilder::default()
    }
}

/// A builder for [`CreateViewInput`](crate::operation::create_view::CreateViewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateViewInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) view_name: ::std::option::Option<::std::string::String>,
    pub(crate) included_properties: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>,
    pub(crate) scope: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<crate::types::SearchFilter>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateViewInputBuilder {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your views.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your views.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your views.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The name of the new view. This name appears in the list of views in Resource Explorer.</p>
    /// <p>The name must be no more than 64 characters long, and can include letters, digits, and the dash (-) character. The name must be unique within its Amazon Web Services Region.</p>
    /// This field is required.
    pub fn view_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.view_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the new view. This name appears in the list of views in Resource Explorer.</p>
    /// <p>The name must be no more than 64 characters long, and can include letters, digits, and the dash (-) character. The name must be unique within its Amazon Web Services Region.</p>
    pub fn set_view_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.view_name = input;
        self
    }
    /// <p>The name of the new view. This name appears in the list of views in Resource Explorer.</p>
    /// <p>The name must be no more than 64 characters long, and can include letters, digits, and the dash (-) character. The name must be unique within its Amazon Web Services Region.</p>
    pub fn get_view_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.view_name
    }
    /// Appends an item to `included_properties`.
    ///
    /// To override the contents of this collection use [`set_included_properties`](Self::set_included_properties).
    ///
    /// <p>Specifies optional fields that you want included in search results from this view. It is a list of objects that each describe a field to include.</p>
    /// <p>The default is an empty list, with no optional fields included in the results.</p>
    pub fn included_properties(mut self, input: crate::types::IncludedProperty) -> Self {
        let mut v = self.included_properties.unwrap_or_default();
        v.push(input);
        self.included_properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies optional fields that you want included in search results from this view. It is a list of objects that each describe a field to include.</p>
    /// <p>The default is an empty list, with no optional fields included in the results.</p>
    pub fn set_included_properties(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>) -> Self {
        self.included_properties = input;
        self
    }
    /// <p>Specifies optional fields that you want included in search results from this view. It is a list of objects that each describe a field to include.</p>
    /// <p>The default is an empty list, with no optional fields included in the results.</p>
    pub fn get_included_properties(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>> {
        &self.included_properties
    }
    /// <p>The root ARN of the account, an organizational unit (OU), or an organization ARN. If left empty, the default is account.</p>
    pub fn scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The root ARN of the account, an organizational unit (OU), or an organization ARN. If left empty, the default is account.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope = input;
        self
    }
    /// <p>The root ARN of the account, an organizational unit (OU), or an organization ARN. If left empty, the default is account.</p>
    pub fn get_scope(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope
    }
    /// <p>An array of strings that specify which resources are included in the results of queries made using this view. When you use this view in a <code>Search</code> operation, the filter string is combined with the search's <code>QueryString</code> parameter using a logical <code>AND</code> operator.</p>
    /// <p>For information about the supported syntax, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query reference for Resource Explorer</a> in the <i>Amazon Web Services Resource Explorer User Guide</i>.</p><important>
    /// <p>This query string in the context of this operation supports only <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-filters">filter prefixes</a> with optional <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-operators">operators</a>. It doesn't support free-form text. For example, the string <code>region:us* service:ec2 -tag:stage=prod</code> includes all Amazon EC2 resources in any Amazon Web Services Region that begins with the letters <code>us</code> and is <i>not</i> tagged with a key <code>Stage</code> that has the value <code>prod</code>.</p>
    /// </important>
    pub fn filters(mut self, input: crate::types::SearchFilter) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of strings that specify which resources are included in the results of queries made using this view. When you use this view in a <code>Search</code> operation, the filter string is combined with the search's <code>QueryString</code> parameter using a logical <code>AND</code> operator.</p>
    /// <p>For information about the supported syntax, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query reference for Resource Explorer</a> in the <i>Amazon Web Services Resource Explorer User Guide</i>.</p><important>
    /// <p>This query string in the context of this operation supports only <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-filters">filter prefixes</a> with optional <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-operators">operators</a>. It doesn't support free-form text. For example, the string <code>region:us* service:ec2 -tag:stage=prod</code> includes all Amazon EC2 resources in any Amazon Web Services Region that begins with the letters <code>us</code> and is <i>not</i> tagged with a key <code>Stage</code> that has the value <code>prod</code>.</p>
    /// </important>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::SearchFilter>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An array of strings that specify which resources are included in the results of queries made using this view. When you use this view in a <code>Search</code> operation, the filter string is combined with the search's <code>QueryString</code> parameter using a logical <code>AND</code> operator.</p>
    /// <p>For information about the supported syntax, see <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html">Search query reference for Resource Explorer</a> in the <i>Amazon Web Services Resource Explorer User Guide</i>.</p><important>
    /// <p>This query string in the context of this operation supports only <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-filters">filter prefixes</a> with optional <a href="https://docs.aws.amazon.com/resource-explorer/latest/userguide/using-search-query-syntax.html#query-syntax-operators">operators</a>. It doesn't support free-form text. For example, the string <code>region:us* service:ec2 -tag:stage=prod</code> includes all Amazon EC2 resources in any Amazon Web Services Region that begins with the letters <code>us</code> and is <i>not</i> tagged with a key <code>Stage</code> that has the value <code>prod</code>.</p>
    /// </important>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::SearchFilter> {
        &self.filters
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tag key and value pairs that are attached to the view.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tag key and value pairs that are attached to the view.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tag key and value pairs that are attached to the view.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateViewInput`](crate::operation::create_view::CreateViewInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_view::CreateViewInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_view::CreateViewInput {
            client_token: self.client_token,
            view_name: self.view_name,
            included_properties: self.included_properties,
            scope: self.scope,
            filters: self.filters,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for CreateViewInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateViewInputBuilder");
        formatter.field("client_token", &self.client_token);
        formatter.field("view_name", &self.view_name);
        formatter.field("included_properties", &self.included_properties);
        formatter.field("scope", &self.scope);
        formatter.field("filters", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
