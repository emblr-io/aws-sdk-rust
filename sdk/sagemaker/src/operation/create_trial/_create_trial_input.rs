// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTrialInput {
    /// <p>The name of the trial. The name must be unique in your Amazon Web Services account and is not case-sensitive.</p>
    pub trial_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the trial as displayed. The name doesn't need to be unique. If <code>DisplayName</code> isn't specified, <code>TrialName</code> is displayed.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the experiment to associate the trial with.</p>
    pub experiment_name: ::std::option::Option<::std::string::String>,
    /// <p>Metadata properties of the tracking entity, trial, or trial component.</p>
    pub metadata_properties: ::std::option::Option<crate::types::MetadataProperties>,
    /// <p>A list of tags to associate with the trial. You can use <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API to search on the tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateTrialInput {
    /// <p>The name of the trial. The name must be unique in your Amazon Web Services account and is not case-sensitive.</p>
    pub fn trial_name(&self) -> ::std::option::Option<&str> {
        self.trial_name.as_deref()
    }
    /// <p>The name of the trial as displayed. The name doesn't need to be unique. If <code>DisplayName</code> isn't specified, <code>TrialName</code> is displayed.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The name of the experiment to associate the trial with.</p>
    pub fn experiment_name(&self) -> ::std::option::Option<&str> {
        self.experiment_name.as_deref()
    }
    /// <p>Metadata properties of the tracking entity, trial, or trial component.</p>
    pub fn metadata_properties(&self) -> ::std::option::Option<&crate::types::MetadataProperties> {
        self.metadata_properties.as_ref()
    }
    /// <p>A list of tags to associate with the trial. You can use <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API to search on the tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateTrialInput {
    /// Creates a new builder-style object to manufacture [`CreateTrialInput`](crate::operation::create_trial::CreateTrialInput).
    pub fn builder() -> crate::operation::create_trial::builders::CreateTrialInputBuilder {
        crate::operation::create_trial::builders::CreateTrialInputBuilder::default()
    }
}

/// A builder for [`CreateTrialInput`](crate::operation::create_trial::CreateTrialInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTrialInputBuilder {
    pub(crate) trial_name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) experiment_name: ::std::option::Option<::std::string::String>,
    pub(crate) metadata_properties: ::std::option::Option<crate::types::MetadataProperties>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateTrialInputBuilder {
    /// <p>The name of the trial. The name must be unique in your Amazon Web Services account and is not case-sensitive.</p>
    /// This field is required.
    pub fn trial_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trial_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trial. The name must be unique in your Amazon Web Services account and is not case-sensitive.</p>
    pub fn set_trial_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trial_name = input;
        self
    }
    /// <p>The name of the trial. The name must be unique in your Amazon Web Services account and is not case-sensitive.</p>
    pub fn get_trial_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.trial_name
    }
    /// <p>The name of the trial as displayed. The name doesn't need to be unique. If <code>DisplayName</code> isn't specified, <code>TrialName</code> is displayed.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trial as displayed. The name doesn't need to be unique. If <code>DisplayName</code> isn't specified, <code>TrialName</code> is displayed.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The name of the trial as displayed. The name doesn't need to be unique. If <code>DisplayName</code> isn't specified, <code>TrialName</code> is displayed.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The name of the experiment to associate the trial with.</p>
    /// This field is required.
    pub fn experiment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.experiment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the experiment to associate the trial with.</p>
    pub fn set_experiment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.experiment_name = input;
        self
    }
    /// <p>The name of the experiment to associate the trial with.</p>
    pub fn get_experiment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.experiment_name
    }
    /// <p>Metadata properties of the tracking entity, trial, or trial component.</p>
    pub fn metadata_properties(mut self, input: crate::types::MetadataProperties) -> Self {
        self.metadata_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata properties of the tracking entity, trial, or trial component.</p>
    pub fn set_metadata_properties(mut self, input: ::std::option::Option<crate::types::MetadataProperties>) -> Self {
        self.metadata_properties = input;
        self
    }
    /// <p>Metadata properties of the tracking entity, trial, or trial component.</p>
    pub fn get_metadata_properties(&self) -> &::std::option::Option<crate::types::MetadataProperties> {
        &self.metadata_properties
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to associate with the trial. You can use <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API to search on the tags.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to associate with the trial. You can use <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API to search on the tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to associate with the trial. You can use <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_Search.html">Search</a> API to search on the tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateTrialInput`](crate::operation::create_trial::CreateTrialInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_trial::CreateTrialInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_trial::CreateTrialInput {
            trial_name: self.trial_name,
            display_name: self.display_name,
            experiment_name: self.experiment_name,
            metadata_properties: self.metadata_properties,
            tags: self.tags,
        })
    }
}
