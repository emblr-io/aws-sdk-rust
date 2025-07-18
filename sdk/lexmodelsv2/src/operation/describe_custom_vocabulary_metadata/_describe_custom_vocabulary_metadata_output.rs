// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCustomVocabularyMetadataOutput {
    /// <p>The identifier of the bot that contains the custom vocabulary.</p>
    pub bot_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the bot that contains the custom vocabulary to describe.</p>
    pub bot_version: ::std::option::Option<::std::string::String>,
    /// <p>The locale that contains the custom vocabulary to describe.</p>
    pub locale_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the custom vocabulary. If the status is <code>Ready</code> the custom vocabulary is ready to use.</p>
    pub custom_vocabulary_status: ::std::option::Option<crate::types::CustomVocabularyStatus>,
    /// <p>The date and time that the custom vocabulary was created.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the custom vocabulary was last updated.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeCustomVocabularyMetadataOutput {
    /// <p>The identifier of the bot that contains the custom vocabulary.</p>
    pub fn bot_id(&self) -> ::std::option::Option<&str> {
        self.bot_id.as_deref()
    }
    /// <p>The version of the bot that contains the custom vocabulary to describe.</p>
    pub fn bot_version(&self) -> ::std::option::Option<&str> {
        self.bot_version.as_deref()
    }
    /// <p>The locale that contains the custom vocabulary to describe.</p>
    pub fn locale_id(&self) -> ::std::option::Option<&str> {
        self.locale_id.as_deref()
    }
    /// <p>The status of the custom vocabulary. If the status is <code>Ready</code> the custom vocabulary is ready to use.</p>
    pub fn custom_vocabulary_status(&self) -> ::std::option::Option<&crate::types::CustomVocabularyStatus> {
        self.custom_vocabulary_status.as_ref()
    }
    /// <p>The date and time that the custom vocabulary was created.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The date and time that the custom vocabulary was last updated.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCustomVocabularyMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCustomVocabularyMetadataOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCustomVocabularyMetadataOutput`](crate::operation::describe_custom_vocabulary_metadata::DescribeCustomVocabularyMetadataOutput).
    pub fn builder() -> crate::operation::describe_custom_vocabulary_metadata::builders::DescribeCustomVocabularyMetadataOutputBuilder {
        crate::operation::describe_custom_vocabulary_metadata::builders::DescribeCustomVocabularyMetadataOutputBuilder::default()
    }
}

/// A builder for [`DescribeCustomVocabularyMetadataOutput`](crate::operation::describe_custom_vocabulary_metadata::DescribeCustomVocabularyMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCustomVocabularyMetadataOutputBuilder {
    pub(crate) bot_id: ::std::option::Option<::std::string::String>,
    pub(crate) bot_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale_id: ::std::option::Option<::std::string::String>,
    pub(crate) custom_vocabulary_status: ::std::option::Option<crate::types::CustomVocabularyStatus>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeCustomVocabularyMetadataOutputBuilder {
    /// <p>The identifier of the bot that contains the custom vocabulary.</p>
    pub fn bot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the bot that contains the custom vocabulary.</p>
    pub fn set_bot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_id = input;
        self
    }
    /// <p>The identifier of the bot that contains the custom vocabulary.</p>
    pub fn get_bot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_id
    }
    /// <p>The version of the bot that contains the custom vocabulary to describe.</p>
    pub fn bot_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bot_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the bot that contains the custom vocabulary to describe.</p>
    pub fn set_bot_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bot_version = input;
        self
    }
    /// <p>The version of the bot that contains the custom vocabulary to describe.</p>
    pub fn get_bot_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.bot_version
    }
    /// <p>The locale that contains the custom vocabulary to describe.</p>
    pub fn locale_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The locale that contains the custom vocabulary to describe.</p>
    pub fn set_locale_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale_id = input;
        self
    }
    /// <p>The locale that contains the custom vocabulary to describe.</p>
    pub fn get_locale_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale_id
    }
    /// <p>The status of the custom vocabulary. If the status is <code>Ready</code> the custom vocabulary is ready to use.</p>
    pub fn custom_vocabulary_status(mut self, input: crate::types::CustomVocabularyStatus) -> Self {
        self.custom_vocabulary_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the custom vocabulary. If the status is <code>Ready</code> the custom vocabulary is ready to use.</p>
    pub fn set_custom_vocabulary_status(mut self, input: ::std::option::Option<crate::types::CustomVocabularyStatus>) -> Self {
        self.custom_vocabulary_status = input;
        self
    }
    /// <p>The status of the custom vocabulary. If the status is <code>Ready</code> the custom vocabulary is ready to use.</p>
    pub fn get_custom_vocabulary_status(&self) -> &::std::option::Option<crate::types::CustomVocabularyStatus> {
        &self.custom_vocabulary_status
    }
    /// <p>The date and time that the custom vocabulary was created.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the custom vocabulary was created.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The date and time that the custom vocabulary was created.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The date and time that the custom vocabulary was last updated.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the custom vocabulary was last updated.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The date and time that the custom vocabulary was last updated.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCustomVocabularyMetadataOutput`](crate::operation::describe_custom_vocabulary_metadata::DescribeCustomVocabularyMetadataOutput).
    pub fn build(self) -> crate::operation::describe_custom_vocabulary_metadata::DescribeCustomVocabularyMetadataOutput {
        crate::operation::describe_custom_vocabulary_metadata::DescribeCustomVocabularyMetadataOutput {
            bot_id: self.bot_id,
            bot_version: self.bot_version,
            locale_id: self.locale_id,
            custom_vocabulary_status: self.custom_vocabulary_status,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            _request_id: self._request_id,
        }
    }
}
