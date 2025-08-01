// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains the properties for the Kubernetes resources of a job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EksProperties {
    /// <p>The properties for the Kubernetes pod resources of a job.</p>
    pub pod_properties: ::std::option::Option<crate::types::EksPodProperties>,
}
impl EksProperties {
    /// <p>The properties for the Kubernetes pod resources of a job.</p>
    pub fn pod_properties(&self) -> ::std::option::Option<&crate::types::EksPodProperties> {
        self.pod_properties.as_ref()
    }
}
impl EksProperties {
    /// Creates a new builder-style object to manufacture [`EksProperties`](crate::types::EksProperties).
    pub fn builder() -> crate::types::builders::EksPropertiesBuilder {
        crate::types::builders::EksPropertiesBuilder::default()
    }
}

/// A builder for [`EksProperties`](crate::types::EksProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EksPropertiesBuilder {
    pub(crate) pod_properties: ::std::option::Option<crate::types::EksPodProperties>,
}
impl EksPropertiesBuilder {
    /// <p>The properties for the Kubernetes pod resources of a job.</p>
    pub fn pod_properties(mut self, input: crate::types::EksPodProperties) -> Self {
        self.pod_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties for the Kubernetes pod resources of a job.</p>
    pub fn set_pod_properties(mut self, input: ::std::option::Option<crate::types::EksPodProperties>) -> Self {
        self.pod_properties = input;
        self
    }
    /// <p>The properties for the Kubernetes pod resources of a job.</p>
    pub fn get_pod_properties(&self) -> &::std::option::Option<crate::types::EksPodProperties> {
        &self.pod_properties
    }
    /// Consumes the builder and constructs a [`EksProperties`](crate::types::EksProperties).
    pub fn build(self) -> crate::types::EksProperties {
        crate::types::EksProperties {
            pod_properties: self.pod_properties,
        }
    }
}
