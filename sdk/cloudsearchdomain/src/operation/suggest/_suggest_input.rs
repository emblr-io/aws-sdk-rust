// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code>Suggest</code> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SuggestInput {
    /// <p>Specifies the string for which you want to get suggestions.</p>
    pub query: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the name of the suggester to use to find suggested matches.</p>
    pub suggester: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the maximum number of suggestions to return.</p>
    pub size: ::std::option::Option<i64>,
}
impl SuggestInput {
    /// <p>Specifies the string for which you want to get suggestions.</p>
    pub fn query(&self) -> ::std::option::Option<&str> {
        self.query.as_deref()
    }
    /// <p>Specifies the name of the suggester to use to find suggested matches.</p>
    pub fn suggester(&self) -> ::std::option::Option<&str> {
        self.suggester.as_deref()
    }
    /// <p>Specifies the maximum number of suggestions to return.</p>
    pub fn size(&self) -> ::std::option::Option<i64> {
        self.size
    }
}
impl SuggestInput {
    /// Creates a new builder-style object to manufacture [`SuggestInput`](crate::operation::suggest::SuggestInput).
    pub fn builder() -> crate::operation::suggest::builders::SuggestInputBuilder {
        crate::operation::suggest::builders::SuggestInputBuilder::default()
    }
}

/// A builder for [`SuggestInput`](crate::operation::suggest::SuggestInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SuggestInputBuilder {
    pub(crate) query: ::std::option::Option<::std::string::String>,
    pub(crate) suggester: ::std::option::Option<::std::string::String>,
    pub(crate) size: ::std::option::Option<i64>,
}
impl SuggestInputBuilder {
    /// <p>Specifies the string for which you want to get suggestions.</p>
    /// This field is required.
    pub fn query(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the string for which you want to get suggestions.</p>
    pub fn set_query(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query = input;
        self
    }
    /// <p>Specifies the string for which you want to get suggestions.</p>
    pub fn get_query(&self) -> &::std::option::Option<::std::string::String> {
        &self.query
    }
    /// <p>Specifies the name of the suggester to use to find suggested matches.</p>
    /// This field is required.
    pub fn suggester(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.suggester = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the suggester to use to find suggested matches.</p>
    pub fn set_suggester(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.suggester = input;
        self
    }
    /// <p>Specifies the name of the suggester to use to find suggested matches.</p>
    pub fn get_suggester(&self) -> &::std::option::Option<::std::string::String> {
        &self.suggester
    }
    /// <p>Specifies the maximum number of suggestions to return.</p>
    pub fn size(mut self, input: i64) -> Self {
        self.size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum number of suggestions to return.</p>
    pub fn set_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size = input;
        self
    }
    /// <p>Specifies the maximum number of suggestions to return.</p>
    pub fn get_size(&self) -> &::std::option::Option<i64> {
        &self.size
    }
    /// Consumes the builder and constructs a [`SuggestInput`](crate::operation::suggest::SuggestInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::suggest::SuggestInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::suggest::SuggestInput {
            query: self.query,
            suggester: self.suggester,
            size: self.size,
        })
    }
}
