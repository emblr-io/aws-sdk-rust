// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCustomEntityTypeOutput {
    /// <p>The name of the custom pattern that you retrieved.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A regular expression string that is used for detecting sensitive data in a custom pattern.</p>
    pub regex_string: ::std::option::Option<::std::string::String>,
    /// <p>A list of context words if specified when you created the custom pattern. If none of these context words are found within the vicinity of the regular expression the data will not be detected as sensitive data.</p>
    pub context_words: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetCustomEntityTypeOutput {
    /// <p>The name of the custom pattern that you retrieved.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A regular expression string that is used for detecting sensitive data in a custom pattern.</p>
    pub fn regex_string(&self) -> ::std::option::Option<&str> {
        self.regex_string.as_deref()
    }
    /// <p>A list of context words if specified when you created the custom pattern. If none of these context words are found within the vicinity of the regular expression the data will not be detected as sensitive data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.context_words.is_none()`.
    pub fn context_words(&self) -> &[::std::string::String] {
        self.context_words.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetCustomEntityTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCustomEntityTypeOutput {
    /// Creates a new builder-style object to manufacture [`GetCustomEntityTypeOutput`](crate::operation::get_custom_entity_type::GetCustomEntityTypeOutput).
    pub fn builder() -> crate::operation::get_custom_entity_type::builders::GetCustomEntityTypeOutputBuilder {
        crate::operation::get_custom_entity_type::builders::GetCustomEntityTypeOutputBuilder::default()
    }
}

/// A builder for [`GetCustomEntityTypeOutput`](crate::operation::get_custom_entity_type::GetCustomEntityTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCustomEntityTypeOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) regex_string: ::std::option::Option<::std::string::String>,
    pub(crate) context_words: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl GetCustomEntityTypeOutputBuilder {
    /// <p>The name of the custom pattern that you retrieved.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom pattern that you retrieved.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the custom pattern that you retrieved.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A regular expression string that is used for detecting sensitive data in a custom pattern.</p>
    pub fn regex_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regex_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A regular expression string that is used for detecting sensitive data in a custom pattern.</p>
    pub fn set_regex_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regex_string = input;
        self
    }
    /// <p>A regular expression string that is used for detecting sensitive data in a custom pattern.</p>
    pub fn get_regex_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.regex_string
    }
    /// Appends an item to `context_words`.
    ///
    /// To override the contents of this collection use [`set_context_words`](Self::set_context_words).
    ///
    /// <p>A list of context words if specified when you created the custom pattern. If none of these context words are found within the vicinity of the regular expression the data will not be detected as sensitive data.</p>
    pub fn context_words(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.context_words.unwrap_or_default();
        v.push(input.into());
        self.context_words = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of context words if specified when you created the custom pattern. If none of these context words are found within the vicinity of the regular expression the data will not be detected as sensitive data.</p>
    pub fn set_context_words(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.context_words = input;
        self
    }
    /// <p>A list of context words if specified when you created the custom pattern. If none of these context words are found within the vicinity of the regular expression the data will not be detected as sensitive data.</p>
    pub fn get_context_words(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.context_words
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCustomEntityTypeOutput`](crate::operation::get_custom_entity_type::GetCustomEntityTypeOutput).
    pub fn build(self) -> crate::operation::get_custom_entity_type::GetCustomEntityTypeOutput {
        crate::operation::get_custom_entity_type::GetCustomEntityTypeOutput {
            name: self.name,
            regex_string: self.regex_string,
            context_words: self.context_words,
            _request_id: self._request_id,
        }
    }
}
