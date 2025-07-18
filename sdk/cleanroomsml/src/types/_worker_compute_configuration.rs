// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration information about the compute workers that perform the transform job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkerComputeConfiguration {
    /// <p>The instance type of the compute workers that are used.</p>
    pub r#type: crate::types::WorkerComputeType,
    /// <p>The number of compute workers that are used.</p>
    pub number: i32,
}
impl WorkerComputeConfiguration {
    /// <p>The instance type of the compute workers that are used.</p>
    pub fn r#type(&self) -> &crate::types::WorkerComputeType {
        &self.r#type
    }
    /// <p>The number of compute workers that are used.</p>
    pub fn number(&self) -> i32 {
        self.number
    }
}
impl WorkerComputeConfiguration {
    /// Creates a new builder-style object to manufacture [`WorkerComputeConfiguration`](crate::types::WorkerComputeConfiguration).
    pub fn builder() -> crate::types::builders::WorkerComputeConfigurationBuilder {
        crate::types::builders::WorkerComputeConfigurationBuilder::default()
    }
}

/// A builder for [`WorkerComputeConfiguration`](crate::types::WorkerComputeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkerComputeConfigurationBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::WorkerComputeType>,
    pub(crate) number: ::std::option::Option<i32>,
}
impl WorkerComputeConfigurationBuilder {
    /// <p>The instance type of the compute workers that are used.</p>
    pub fn r#type(mut self, input: crate::types::WorkerComputeType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type of the compute workers that are used.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::WorkerComputeType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The instance type of the compute workers that are used.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::WorkerComputeType> {
        &self.r#type
    }
    /// <p>The number of compute workers that are used.</p>
    pub fn number(mut self, input: i32) -> Self {
        self.number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of compute workers that are used.</p>
    pub fn set_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number = input;
        self
    }
    /// <p>The number of compute workers that are used.</p>
    pub fn get_number(&self) -> &::std::option::Option<i32> {
        &self.number
    }
    /// Consumes the builder and constructs a [`WorkerComputeConfiguration`](crate::types::WorkerComputeConfiguration).
    pub fn build(self) -> crate::types::WorkerComputeConfiguration {
        crate::types::WorkerComputeConfiguration {
            r#type: self.r#type.unwrap_or(
                "CR.1X"
                    .parse::<crate::types::WorkerComputeType>()
                    .expect("static value validated to member"),
            ),
            number: self.number.unwrap_or(16),
        }
    }
}
