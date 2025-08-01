// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRunGroupInput {
    /// <p>The group's ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A name for the group.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of CPUs to use.</p>
    pub max_cpus: ::std::option::Option<i32>,
    /// <p>The maximum number of concurrent runs for the group.</p>
    pub max_runs: ::std::option::Option<i32>,
    /// <p>A maximum run time for the group in minutes.</p>
    pub max_duration: ::std::option::Option<i32>,
    /// <p>The maximum GPUs that can be used by a run group.</p>
    pub max_gpus: ::std::option::Option<i32>,
}
impl UpdateRunGroupInput {
    /// <p>The group's ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A name for the group.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The maximum number of CPUs to use.</p>
    pub fn max_cpus(&self) -> ::std::option::Option<i32> {
        self.max_cpus
    }
    /// <p>The maximum number of concurrent runs for the group.</p>
    pub fn max_runs(&self) -> ::std::option::Option<i32> {
        self.max_runs
    }
    /// <p>A maximum run time for the group in minutes.</p>
    pub fn max_duration(&self) -> ::std::option::Option<i32> {
        self.max_duration
    }
    /// <p>The maximum GPUs that can be used by a run group.</p>
    pub fn max_gpus(&self) -> ::std::option::Option<i32> {
        self.max_gpus
    }
}
impl UpdateRunGroupInput {
    /// Creates a new builder-style object to manufacture [`UpdateRunGroupInput`](crate::operation::update_run_group::UpdateRunGroupInput).
    pub fn builder() -> crate::operation::update_run_group::builders::UpdateRunGroupInputBuilder {
        crate::operation::update_run_group::builders::UpdateRunGroupInputBuilder::default()
    }
}

/// A builder for [`UpdateRunGroupInput`](crate::operation::update_run_group::UpdateRunGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRunGroupInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) max_cpus: ::std::option::Option<i32>,
    pub(crate) max_runs: ::std::option::Option<i32>,
    pub(crate) max_duration: ::std::option::Option<i32>,
    pub(crate) max_gpus: ::std::option::Option<i32>,
}
impl UpdateRunGroupInputBuilder {
    /// <p>The group's ID.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The group's ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The group's ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A name for the group.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the group.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the group.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The maximum number of CPUs to use.</p>
    pub fn max_cpus(mut self, input: i32) -> Self {
        self.max_cpus = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of CPUs to use.</p>
    pub fn set_max_cpus(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_cpus = input;
        self
    }
    /// <p>The maximum number of CPUs to use.</p>
    pub fn get_max_cpus(&self) -> &::std::option::Option<i32> {
        &self.max_cpus
    }
    /// <p>The maximum number of concurrent runs for the group.</p>
    pub fn max_runs(mut self, input: i32) -> Self {
        self.max_runs = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of concurrent runs for the group.</p>
    pub fn set_max_runs(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_runs = input;
        self
    }
    /// <p>The maximum number of concurrent runs for the group.</p>
    pub fn get_max_runs(&self) -> &::std::option::Option<i32> {
        &self.max_runs
    }
    /// <p>A maximum run time for the group in minutes.</p>
    pub fn max_duration(mut self, input: i32) -> Self {
        self.max_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A maximum run time for the group in minutes.</p>
    pub fn set_max_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_duration = input;
        self
    }
    /// <p>A maximum run time for the group in minutes.</p>
    pub fn get_max_duration(&self) -> &::std::option::Option<i32> {
        &self.max_duration
    }
    /// <p>The maximum GPUs that can be used by a run group.</p>
    pub fn max_gpus(mut self, input: i32) -> Self {
        self.max_gpus = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum GPUs that can be used by a run group.</p>
    pub fn set_max_gpus(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_gpus = input;
        self
    }
    /// <p>The maximum GPUs that can be used by a run group.</p>
    pub fn get_max_gpus(&self) -> &::std::option::Option<i32> {
        &self.max_gpus
    }
    /// Consumes the builder and constructs a [`UpdateRunGroupInput`](crate::operation::update_run_group::UpdateRunGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_run_group::UpdateRunGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_run_group::UpdateRunGroupInput {
            id: self.id,
            name: self.name,
            max_cpus: self.max_cpus,
            max_runs: self.max_runs,
            max_duration: self.max_duration,
            max_gpus: self.max_gpus,
        })
    }
}
