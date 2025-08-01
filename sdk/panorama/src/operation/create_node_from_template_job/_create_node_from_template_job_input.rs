// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateNodeFromTemplateJobInput {
    /// <p>The type of node.</p>
    pub template_type: ::std::option::Option<crate::types::TemplateType>,
    /// <p>An output package name for the node.</p>
    pub output_package_name: ::std::option::Option<::std::string::String>,
    /// <p>An output package version for the node.</p>
    pub output_package_version: ::std::option::Option<::std::string::String>,
    /// <p>A name for the node.</p>
    pub node_name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the node.</p>
    pub node_description: ::std::option::Option<::std::string::String>,
    /// <p>Template parameters for the node.</p>
    pub template_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Tags for the job.</p>
    pub job_tags: ::std::option::Option<::std::vec::Vec<crate::types::JobResourceTags>>,
}
impl CreateNodeFromTemplateJobInput {
    /// <p>The type of node.</p>
    pub fn template_type(&self) -> ::std::option::Option<&crate::types::TemplateType> {
        self.template_type.as_ref()
    }
    /// <p>An output package name for the node.</p>
    pub fn output_package_name(&self) -> ::std::option::Option<&str> {
        self.output_package_name.as_deref()
    }
    /// <p>An output package version for the node.</p>
    pub fn output_package_version(&self) -> ::std::option::Option<&str> {
        self.output_package_version.as_deref()
    }
    /// <p>A name for the node.</p>
    pub fn node_name(&self) -> ::std::option::Option<&str> {
        self.node_name.as_deref()
    }
    /// <p>A description for the node.</p>
    pub fn node_description(&self) -> ::std::option::Option<&str> {
        self.node_description.as_deref()
    }
    /// <p>Template parameters for the node.</p>
    pub fn template_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.template_parameters.as_ref()
    }
    /// <p>Tags for the job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.job_tags.is_none()`.
    pub fn job_tags(&self) -> &[crate::types::JobResourceTags] {
        self.job_tags.as_deref().unwrap_or_default()
    }
}
impl CreateNodeFromTemplateJobInput {
    /// Creates a new builder-style object to manufacture [`CreateNodeFromTemplateJobInput`](crate::operation::create_node_from_template_job::CreateNodeFromTemplateJobInput).
    pub fn builder() -> crate::operation::create_node_from_template_job::builders::CreateNodeFromTemplateJobInputBuilder {
        crate::operation::create_node_from_template_job::builders::CreateNodeFromTemplateJobInputBuilder::default()
    }
}

/// A builder for [`CreateNodeFromTemplateJobInput`](crate::operation::create_node_from_template_job::CreateNodeFromTemplateJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateNodeFromTemplateJobInputBuilder {
    pub(crate) template_type: ::std::option::Option<crate::types::TemplateType>,
    pub(crate) output_package_name: ::std::option::Option<::std::string::String>,
    pub(crate) output_package_version: ::std::option::Option<::std::string::String>,
    pub(crate) node_name: ::std::option::Option<::std::string::String>,
    pub(crate) node_description: ::std::option::Option<::std::string::String>,
    pub(crate) template_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) job_tags: ::std::option::Option<::std::vec::Vec<crate::types::JobResourceTags>>,
}
impl CreateNodeFromTemplateJobInputBuilder {
    /// <p>The type of node.</p>
    /// This field is required.
    pub fn template_type(mut self, input: crate::types::TemplateType) -> Self {
        self.template_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of node.</p>
    pub fn set_template_type(mut self, input: ::std::option::Option<crate::types::TemplateType>) -> Self {
        self.template_type = input;
        self
    }
    /// <p>The type of node.</p>
    pub fn get_template_type(&self) -> &::std::option::Option<crate::types::TemplateType> {
        &self.template_type
    }
    /// <p>An output package name for the node.</p>
    /// This field is required.
    pub fn output_package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An output package name for the node.</p>
    pub fn set_output_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_package_name = input;
        self
    }
    /// <p>An output package name for the node.</p>
    pub fn get_output_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_package_name
    }
    /// <p>An output package version for the node.</p>
    /// This field is required.
    pub fn output_package_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_package_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An output package version for the node.</p>
    pub fn set_output_package_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_package_version = input;
        self
    }
    /// <p>An output package version for the node.</p>
    pub fn get_output_package_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_package_version
    }
    /// <p>A name for the node.</p>
    /// This field is required.
    pub fn node_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the node.</p>
    pub fn set_node_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_name = input;
        self
    }
    /// <p>A name for the node.</p>
    pub fn get_node_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_name
    }
    /// <p>A description for the node.</p>
    pub fn node_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the node.</p>
    pub fn set_node_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node_description = input;
        self
    }
    /// <p>A description for the node.</p>
    pub fn get_node_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.node_description
    }
    /// Adds a key-value pair to `template_parameters`.
    ///
    /// To override the contents of this collection use [`set_template_parameters`](Self::set_template_parameters).
    ///
    /// <p>Template parameters for the node.</p>
    pub fn template_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.template_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.template_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Template parameters for the node.</p>
    pub fn set_template_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.template_parameters = input;
        self
    }
    /// <p>Template parameters for the node.</p>
    pub fn get_template_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.template_parameters
    }
    /// Appends an item to `job_tags`.
    ///
    /// To override the contents of this collection use [`set_job_tags`](Self::set_job_tags).
    ///
    /// <p>Tags for the job.</p>
    pub fn job_tags(mut self, input: crate::types::JobResourceTags) -> Self {
        let mut v = self.job_tags.unwrap_or_default();
        v.push(input);
        self.job_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags for the job.</p>
    pub fn set_job_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::JobResourceTags>>) -> Self {
        self.job_tags = input;
        self
    }
    /// <p>Tags for the job.</p>
    pub fn get_job_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::JobResourceTags>> {
        &self.job_tags
    }
    /// Consumes the builder and constructs a [`CreateNodeFromTemplateJobInput`](crate::operation::create_node_from_template_job::CreateNodeFromTemplateJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_node_from_template_job::CreateNodeFromTemplateJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_node_from_template_job::CreateNodeFromTemplateJobInput {
            template_type: self.template_type,
            output_package_name: self.output_package_name,
            output_package_version: self.output_package_version,
            node_name: self.node_name,
            node_description: self.node_description,
            template_parameters: self.template_parameters,
            job_tags: self.job_tags,
        })
    }
}
