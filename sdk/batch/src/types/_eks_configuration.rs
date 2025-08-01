// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration for the Amazon EKS cluster that supports the Batch compute environment. The cluster must exist before the compute environment can be created.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EksConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the Amazon EKS cluster. An example is <code>arn:<i>aws</i>:eks:<i>us-east-1</i>:<i>123456789012</i>:cluster/<i>ClusterForBatch</i> </code>.</p>
    pub eks_cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the Amazon EKS cluster. Batch manages pods in this namespace. The value can't left empty or null. It must be fewer than 64 characters long, can't be set to <code>default</code>, can't start with "<code>kube-</code>," and must match this regular expression: <code>^\[a-z0-9\](\[-a-z0-9\]*\[a-z0-9\])?$</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/">Namespaces</a> in the Kubernetes documentation.</p>
    pub kubernetes_namespace: ::std::option::Option<::std::string::String>,
}
impl EksConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the Amazon EKS cluster. An example is <code>arn:<i>aws</i>:eks:<i>us-east-1</i>:<i>123456789012</i>:cluster/<i>ClusterForBatch</i> </code>.</p>
    pub fn eks_cluster_arn(&self) -> ::std::option::Option<&str> {
        self.eks_cluster_arn.as_deref()
    }
    /// <p>The namespace of the Amazon EKS cluster. Batch manages pods in this namespace. The value can't left empty or null. It must be fewer than 64 characters long, can't be set to <code>default</code>, can't start with "<code>kube-</code>," and must match this regular expression: <code>^\[a-z0-9\](\[-a-z0-9\]*\[a-z0-9\])?$</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/">Namespaces</a> in the Kubernetes documentation.</p>
    pub fn kubernetes_namespace(&self) -> ::std::option::Option<&str> {
        self.kubernetes_namespace.as_deref()
    }
}
impl EksConfiguration {
    /// Creates a new builder-style object to manufacture [`EksConfiguration`](crate::types::EksConfiguration).
    pub fn builder() -> crate::types::builders::EksConfigurationBuilder {
        crate::types::builders::EksConfigurationBuilder::default()
    }
}

/// A builder for [`EksConfiguration`](crate::types::EksConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EksConfigurationBuilder {
    pub(crate) eks_cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) kubernetes_namespace: ::std::option::Option<::std::string::String>,
}
impl EksConfigurationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Amazon EKS cluster. An example is <code>arn:<i>aws</i>:eks:<i>us-east-1</i>:<i>123456789012</i>:cluster/<i>ClusterForBatch</i> </code>.</p>
    /// This field is required.
    pub fn eks_cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.eks_cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon EKS cluster. An example is <code>arn:<i>aws</i>:eks:<i>us-east-1</i>:<i>123456789012</i>:cluster/<i>ClusterForBatch</i> </code>.</p>
    pub fn set_eks_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.eks_cluster_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon EKS cluster. An example is <code>arn:<i>aws</i>:eks:<i>us-east-1</i>:<i>123456789012</i>:cluster/<i>ClusterForBatch</i> </code>.</p>
    pub fn get_eks_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.eks_cluster_arn
    }
    /// <p>The namespace of the Amazon EKS cluster. Batch manages pods in this namespace. The value can't left empty or null. It must be fewer than 64 characters long, can't be set to <code>default</code>, can't start with "<code>kube-</code>," and must match this regular expression: <code>^\[a-z0-9\](\[-a-z0-9\]*\[a-z0-9\])?$</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/">Namespaces</a> in the Kubernetes documentation.</p>
    /// This field is required.
    pub fn kubernetes_namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kubernetes_namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the Amazon EKS cluster. Batch manages pods in this namespace. The value can't left empty or null. It must be fewer than 64 characters long, can't be set to <code>default</code>, can't start with "<code>kube-</code>," and must match this regular expression: <code>^\[a-z0-9\](\[-a-z0-9\]*\[a-z0-9\])?$</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/">Namespaces</a> in the Kubernetes documentation.</p>
    pub fn set_kubernetes_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kubernetes_namespace = input;
        self
    }
    /// <p>The namespace of the Amazon EKS cluster. Batch manages pods in this namespace. The value can't left empty or null. It must be fewer than 64 characters long, can't be set to <code>default</code>, can't start with "<code>kube-</code>," and must match this regular expression: <code>^\[a-z0-9\](\[-a-z0-9\]*\[a-z0-9\])?$</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/">Namespaces</a> in the Kubernetes documentation.</p>
    pub fn get_kubernetes_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.kubernetes_namespace
    }
    /// Consumes the builder and constructs a [`EksConfiguration`](crate::types::EksConfiguration).
    pub fn build(self) -> crate::types::EksConfiguration {
        crate::types::EksConfiguration {
            eks_cluster_arn: self.eks_cluster_arn,
            kubernetes_namespace: self.kubernetes_namespace,
        }
    }
}
