// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>BatchGetOnPremisesInstances</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetOnPremisesInstancesInput {
    /// <p>The names of the on-premises instances about which to get information. The maximum number of instance names you can specify is 25.</p>
    pub instance_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetOnPremisesInstancesInput {
    /// <p>The names of the on-premises instances about which to get information. The maximum number of instance names you can specify is 25.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_names.is_none()`.
    pub fn instance_names(&self) -> &[::std::string::String] {
        self.instance_names.as_deref().unwrap_or_default()
    }
}
impl BatchGetOnPremisesInstancesInput {
    /// Creates a new builder-style object to manufacture [`BatchGetOnPremisesInstancesInput`](crate::operation::batch_get_on_premises_instances::BatchGetOnPremisesInstancesInput).
    pub fn builder() -> crate::operation::batch_get_on_premises_instances::builders::BatchGetOnPremisesInstancesInputBuilder {
        crate::operation::batch_get_on_premises_instances::builders::BatchGetOnPremisesInstancesInputBuilder::default()
    }
}

/// A builder for [`BatchGetOnPremisesInstancesInput`](crate::operation::batch_get_on_premises_instances::BatchGetOnPremisesInstancesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetOnPremisesInstancesInputBuilder {
    pub(crate) instance_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetOnPremisesInstancesInputBuilder {
    /// Appends an item to `instance_names`.
    ///
    /// To override the contents of this collection use [`set_instance_names`](Self::set_instance_names).
    ///
    /// <p>The names of the on-premises instances about which to get information. The maximum number of instance names you can specify is 25.</p>
    pub fn instance_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_names.unwrap_or_default();
        v.push(input.into());
        self.instance_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the on-premises instances about which to get information. The maximum number of instance names you can specify is 25.</p>
    pub fn set_instance_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_names = input;
        self
    }
    /// <p>The names of the on-premises instances about which to get information. The maximum number of instance names you can specify is 25.</p>
    pub fn get_instance_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_names
    }
    /// Consumes the builder and constructs a [`BatchGetOnPremisesInstancesInput`](crate::operation::batch_get_on_premises_instances::BatchGetOnPremisesInstancesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_get_on_premises_instances::BatchGetOnPremisesInstancesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::batch_get_on_premises_instances::BatchGetOnPremisesInstancesInput {
            instance_names: self.instance_names,
        })
    }
}
