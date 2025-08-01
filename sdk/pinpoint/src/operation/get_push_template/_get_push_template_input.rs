// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPushTemplateInput {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the version of the message template to update, retrieve information about, or delete. To retrieve identifiers and other information for all the versions of a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If specified, this value must match the identifier for an existing template version. If specified for an update operation, this value must match the identifier for the latest existing version of the template. This restriction helps ensure that race conditions don't occur.</p>
    /// <p>If you don't specify a value for this parameter, Amazon Pinpoint does the following:</p>
    /// <ul>
    /// <li>
    /// <p>For a get operation, retrieves information about the active version of the template.</p></li>
    /// <li>
    /// <p>For an update operation, saves the updates to (overwrites) the latest existing version of the template, if the create-new-version parameter isn't used or is set to false.</p></li>
    /// <li>
    /// <p>For a delete operation, deletes the template, including all versions of the template.</p></li>
    /// </ul>
    pub version: ::std::option::Option<::std::string::String>,
}
impl GetPushTemplateInput {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The unique identifier for the version of the message template to update, retrieve information about, or delete. To retrieve identifiers and other information for all the versions of a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If specified, this value must match the identifier for an existing template version. If specified for an update operation, this value must match the identifier for the latest existing version of the template. This restriction helps ensure that race conditions don't occur.</p>
    /// <p>If you don't specify a value for this parameter, Amazon Pinpoint does the following:</p>
    /// <ul>
    /// <li>
    /// <p>For a get operation, retrieves information about the active version of the template.</p></li>
    /// <li>
    /// <p>For an update operation, saves the updates to (overwrites) the latest existing version of the template, if the create-new-version parameter isn't used or is set to false.</p></li>
    /// <li>
    /// <p>For a delete operation, deletes the template, including all versions of the template.</p></li>
    /// </ul>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl GetPushTemplateInput {
    /// Creates a new builder-style object to manufacture [`GetPushTemplateInput`](crate::operation::get_push_template::GetPushTemplateInput).
    pub fn builder() -> crate::operation::get_push_template::builders::GetPushTemplateInputBuilder {
        crate::operation::get_push_template::builders::GetPushTemplateInputBuilder::default()
    }
}

/// A builder for [`GetPushTemplateInput`](crate::operation::get_push_template::GetPushTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPushTemplateInputBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl GetPushTemplateInputBuilder {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The unique identifier for the version of the message template to update, retrieve information about, or delete. To retrieve identifiers and other information for all the versions of a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If specified, this value must match the identifier for an existing template version. If specified for an update operation, this value must match the identifier for the latest existing version of the template. This restriction helps ensure that race conditions don't occur.</p>
    /// <p>If you don't specify a value for this parameter, Amazon Pinpoint does the following:</p>
    /// <ul>
    /// <li>
    /// <p>For a get operation, retrieves information about the active version of the template.</p></li>
    /// <li>
    /// <p>For an update operation, saves the updates to (overwrites) the latest existing version of the template, if the create-new-version parameter isn't used or is set to false.</p></li>
    /// <li>
    /// <p>For a delete operation, deletes the template, including all versions of the template.</p></li>
    /// </ul>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the version of the message template to update, retrieve information about, or delete. To retrieve identifiers and other information for all the versions of a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If specified, this value must match the identifier for an existing template version. If specified for an update operation, this value must match the identifier for the latest existing version of the template. This restriction helps ensure that race conditions don't occur.</p>
    /// <p>If you don't specify a value for this parameter, Amazon Pinpoint does the following:</p>
    /// <ul>
    /// <li>
    /// <p>For a get operation, retrieves information about the active version of the template.</p></li>
    /// <li>
    /// <p>For an update operation, saves the updates to (overwrites) the latest existing version of the template, if the create-new-version parameter isn't used or is set to false.</p></li>
    /// <li>
    /// <p>For a delete operation, deletes the template, including all versions of the template.</p></li>
    /// </ul>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The unique identifier for the version of the message template to update, retrieve information about, or delete. To retrieve identifiers and other information for all the versions of a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If specified, this value must match the identifier for an existing template version. If specified for an update operation, this value must match the identifier for the latest existing version of the template. This restriction helps ensure that race conditions don't occur.</p>
    /// <p>If you don't specify a value for this parameter, Amazon Pinpoint does the following:</p>
    /// <ul>
    /// <li>
    /// <p>For a get operation, retrieves information about the active version of the template.</p></li>
    /// <li>
    /// <p>For an update operation, saves the updates to (overwrites) the latest existing version of the template, if the create-new-version parameter isn't used or is set to false.</p></li>
    /// <li>
    /// <p>For a delete operation, deletes the template, including all versions of the template.</p></li>
    /// </ul>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`GetPushTemplateInput`](crate::operation::get_push_template::GetPushTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_push_template::GetPushTemplateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_push_template::GetPushTemplateInput {
            template_name: self.template_name,
            version: self.version,
        })
    }
}
