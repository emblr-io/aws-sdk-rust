// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the configuration information for the document fields/attributes that you want to base query suggestions on.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttributeSuggestionsGetConfig {
    /// <p>The list of document field/attribute keys or field names to use for query suggestions. If the content within any of the fields match what your user starts typing as their query, then the field content is returned as a query suggestion.</p>
    pub suggestion_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The list of additional document field/attribute keys or field names to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub additional_response_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters the search results based on document fields/attributes.</p>
    pub attribute_filter: ::std::option::Option<crate::types::AttributeFilter>,
    /// <p>Applies user context filtering so that only users who are given access to certain documents see these document in their search results.</p>
    pub user_context: ::std::option::Option<crate::types::UserContext>,
}
impl AttributeSuggestionsGetConfig {
    /// <p>The list of document field/attribute keys or field names to use for query suggestions. If the content within any of the fields match what your user starts typing as their query, then the field content is returned as a query suggestion.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.suggestion_attributes.is_none()`.
    pub fn suggestion_attributes(&self) -> &[::std::string::String] {
        self.suggestion_attributes.as_deref().unwrap_or_default()
    }
    /// <p>The list of additional document field/attribute keys or field names to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_response_attributes.is_none()`.
    pub fn additional_response_attributes(&self) -> &[::std::string::String] {
        self.additional_response_attributes.as_deref().unwrap_or_default()
    }
    /// <p>Filters the search results based on document fields/attributes.</p>
    pub fn attribute_filter(&self) -> ::std::option::Option<&crate::types::AttributeFilter> {
        self.attribute_filter.as_ref()
    }
    /// <p>Applies user context filtering so that only users who are given access to certain documents see these document in their search results.</p>
    pub fn user_context(&self) -> ::std::option::Option<&crate::types::UserContext> {
        self.user_context.as_ref()
    }
}
impl AttributeSuggestionsGetConfig {
    /// Creates a new builder-style object to manufacture [`AttributeSuggestionsGetConfig`](crate::types::AttributeSuggestionsGetConfig).
    pub fn builder() -> crate::types::builders::AttributeSuggestionsGetConfigBuilder {
        crate::types::builders::AttributeSuggestionsGetConfigBuilder::default()
    }
}

/// A builder for [`AttributeSuggestionsGetConfig`](crate::types::AttributeSuggestionsGetConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttributeSuggestionsGetConfigBuilder {
    pub(crate) suggestion_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) additional_response_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) attribute_filter: ::std::option::Option<crate::types::AttributeFilter>,
    pub(crate) user_context: ::std::option::Option<crate::types::UserContext>,
}
impl AttributeSuggestionsGetConfigBuilder {
    /// Appends an item to `suggestion_attributes`.
    ///
    /// To override the contents of this collection use [`set_suggestion_attributes`](Self::set_suggestion_attributes).
    ///
    /// <p>The list of document field/attribute keys or field names to use for query suggestions. If the content within any of the fields match what your user starts typing as their query, then the field content is returned as a query suggestion.</p>
    pub fn suggestion_attributes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.suggestion_attributes.unwrap_or_default();
        v.push(input.into());
        self.suggestion_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of document field/attribute keys or field names to use for query suggestions. If the content within any of the fields match what your user starts typing as their query, then the field content is returned as a query suggestion.</p>
    pub fn set_suggestion_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.suggestion_attributes = input;
        self
    }
    /// <p>The list of document field/attribute keys or field names to use for query suggestions. If the content within any of the fields match what your user starts typing as their query, then the field content is returned as a query suggestion.</p>
    pub fn get_suggestion_attributes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.suggestion_attributes
    }
    /// Appends an item to `additional_response_attributes`.
    ///
    /// To override the contents of this collection use [`set_additional_response_attributes`](Self::set_additional_response_attributes).
    ///
    /// <p>The list of additional document field/attribute keys or field names to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn additional_response_attributes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.additional_response_attributes.unwrap_or_default();
        v.push(input.into());
        self.additional_response_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of additional document field/attribute keys or field names to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn set_additional_response_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.additional_response_attributes = input;
        self
    }
    /// <p>The list of additional document field/attribute keys or field names to include in the response. You can use additional fields to provide extra information in the response. Additional fields are not used to based suggestions on.</p>
    pub fn get_additional_response_attributes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.additional_response_attributes
    }
    /// <p>Filters the search results based on document fields/attributes.</p>
    pub fn attribute_filter(mut self, input: crate::types::AttributeFilter) -> Self {
        self.attribute_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters the search results based on document fields/attributes.</p>
    pub fn set_attribute_filter(mut self, input: ::std::option::Option<crate::types::AttributeFilter>) -> Self {
        self.attribute_filter = input;
        self
    }
    /// <p>Filters the search results based on document fields/attributes.</p>
    pub fn get_attribute_filter(&self) -> &::std::option::Option<crate::types::AttributeFilter> {
        &self.attribute_filter
    }
    /// <p>Applies user context filtering so that only users who are given access to certain documents see these document in their search results.</p>
    pub fn user_context(mut self, input: crate::types::UserContext) -> Self {
        self.user_context = ::std::option::Option::Some(input);
        self
    }
    /// <p>Applies user context filtering so that only users who are given access to certain documents see these document in their search results.</p>
    pub fn set_user_context(mut self, input: ::std::option::Option<crate::types::UserContext>) -> Self {
        self.user_context = input;
        self
    }
    /// <p>Applies user context filtering so that only users who are given access to certain documents see these document in their search results.</p>
    pub fn get_user_context(&self) -> &::std::option::Option<crate::types::UserContext> {
        &self.user_context
    }
    /// Consumes the builder and constructs a [`AttributeSuggestionsGetConfig`](crate::types::AttributeSuggestionsGetConfig).
    pub fn build(self) -> crate::types::AttributeSuggestionsGetConfig {
        crate::types::AttributeSuggestionsGetConfig {
            suggestion_attributes: self.suggestion_attributes,
            additional_response_attributes: self.additional_response_attributes,
            attribute_filter: self.attribute_filter,
            user_context: self.user_context,
        }
    }
}
