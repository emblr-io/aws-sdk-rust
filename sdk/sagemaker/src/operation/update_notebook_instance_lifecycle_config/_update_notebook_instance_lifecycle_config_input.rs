// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateNotebookInstanceLifecycleConfigInput {
    /// <p>The name of the lifecycle configuration.</p>
    pub notebook_instance_lifecycle_config_name: ::std::option::Option<::std::string::String>,
    /// <p>The shell script that runs only once, when you create a notebook instance. The shell script must be a base64-encoded string.</p>
    pub on_create: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>,
    /// <p>The shell script that runs every time you start a notebook instance, including when you create the notebook instance. The shell script must be a base64-encoded string.</p>
    pub on_start: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>,
}
impl UpdateNotebookInstanceLifecycleConfigInput {
    /// <p>The name of the lifecycle configuration.</p>
    pub fn notebook_instance_lifecycle_config_name(&self) -> ::std::option::Option<&str> {
        self.notebook_instance_lifecycle_config_name.as_deref()
    }
    /// <p>The shell script that runs only once, when you create a notebook instance. The shell script must be a base64-encoded string.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.on_create.is_none()`.
    pub fn on_create(&self) -> &[crate::types::NotebookInstanceLifecycleHook] {
        self.on_create.as_deref().unwrap_or_default()
    }
    /// <p>The shell script that runs every time you start a notebook instance, including when you create the notebook instance. The shell script must be a base64-encoded string.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.on_start.is_none()`.
    pub fn on_start(&self) -> &[crate::types::NotebookInstanceLifecycleHook] {
        self.on_start.as_deref().unwrap_or_default()
    }
}
impl UpdateNotebookInstanceLifecycleConfigInput {
    /// Creates a new builder-style object to manufacture [`UpdateNotebookInstanceLifecycleConfigInput`](crate::operation::update_notebook_instance_lifecycle_config::UpdateNotebookInstanceLifecycleConfigInput).
    pub fn builder() -> crate::operation::update_notebook_instance_lifecycle_config::builders::UpdateNotebookInstanceLifecycleConfigInputBuilder {
        crate::operation::update_notebook_instance_lifecycle_config::builders::UpdateNotebookInstanceLifecycleConfigInputBuilder::default()
    }
}

/// A builder for [`UpdateNotebookInstanceLifecycleConfigInput`](crate::operation::update_notebook_instance_lifecycle_config::UpdateNotebookInstanceLifecycleConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateNotebookInstanceLifecycleConfigInputBuilder {
    pub(crate) notebook_instance_lifecycle_config_name: ::std::option::Option<::std::string::String>,
    pub(crate) on_create: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>,
    pub(crate) on_start: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>,
}
impl UpdateNotebookInstanceLifecycleConfigInputBuilder {
    /// <p>The name of the lifecycle configuration.</p>
    /// This field is required.
    pub fn notebook_instance_lifecycle_config_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notebook_instance_lifecycle_config_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the lifecycle configuration.</p>
    pub fn set_notebook_instance_lifecycle_config_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notebook_instance_lifecycle_config_name = input;
        self
    }
    /// <p>The name of the lifecycle configuration.</p>
    pub fn get_notebook_instance_lifecycle_config_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.notebook_instance_lifecycle_config_name
    }
    /// Appends an item to `on_create`.
    ///
    /// To override the contents of this collection use [`set_on_create`](Self::set_on_create).
    ///
    /// <p>The shell script that runs only once, when you create a notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn on_create(mut self, input: crate::types::NotebookInstanceLifecycleHook) -> Self {
        let mut v = self.on_create.unwrap_or_default();
        v.push(input);
        self.on_create = ::std::option::Option::Some(v);
        self
    }
    /// <p>The shell script that runs only once, when you create a notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn set_on_create(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>) -> Self {
        self.on_create = input;
        self
    }
    /// <p>The shell script that runs only once, when you create a notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn get_on_create(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>> {
        &self.on_create
    }
    /// Appends an item to `on_start`.
    ///
    /// To override the contents of this collection use [`set_on_start`](Self::set_on_start).
    ///
    /// <p>The shell script that runs every time you start a notebook instance, including when you create the notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn on_start(mut self, input: crate::types::NotebookInstanceLifecycleHook) -> Self {
        let mut v = self.on_start.unwrap_or_default();
        v.push(input);
        self.on_start = ::std::option::Option::Some(v);
        self
    }
    /// <p>The shell script that runs every time you start a notebook instance, including when you create the notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn set_on_start(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>>) -> Self {
        self.on_start = input;
        self
    }
    /// <p>The shell script that runs every time you start a notebook instance, including when you create the notebook instance. The shell script must be a base64-encoded string.</p>
    pub fn get_on_start(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NotebookInstanceLifecycleHook>> {
        &self.on_start
    }
    /// Consumes the builder and constructs a [`UpdateNotebookInstanceLifecycleConfigInput`](crate::operation::update_notebook_instance_lifecycle_config::UpdateNotebookInstanceLifecycleConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_notebook_instance_lifecycle_config::UpdateNotebookInstanceLifecycleConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_notebook_instance_lifecycle_config::UpdateNotebookInstanceLifecycleConfigInput {
                notebook_instance_lifecycle_config_name: self.notebook_instance_lifecycle_config_name,
                on_create: self.on_create,
                on_start: self.on_start,
            },
        )
    }
}
