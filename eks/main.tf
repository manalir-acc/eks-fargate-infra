data "aws_eks_cluster" "cluster" {
  name = var.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.cluster_id
}

data "aws_caller_identity" "current" {}

resource "aws_eks_cluster" "eks_cluster" {
  name     = "${var.cluster_name}-${var.environment}"
   
  role_arn = aws_iam_role.eks_cluster_role.arn
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
 # cluster_addons = aws_eks_addon.coredns.addon_name
  version  = var.kubernetes_version
   vpc_config {
    subnet_ids =  concat(var.public_subnets, var.private_subnets)
  }
   
   timeouts {
     delete    =  "30m"
   }
  
  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy1,
    aws_iam_role_policy_attachment.AmazonEKSVPCResourceController1,
    aws_cloudwatch_log_group.cloudwatch_log_group
  ]
}

resource "aws_eks_fargate_profile" "coredns" {
  cluster_name           = aws_eks_cluster.eks_cluster.name
  fargate_profile_name   = "coredns"
  pod_execution_role_arn = aws_iam_role.eks_fargate_role.arn
  subnet_ids             = var.private_subnets
  selector {
    namespace = "kube-system"
    labels = {
      k8s-app = "kube-dns"
    }
  }
}
#resource "null_resource" "k8s_patcher" {
#  depends_on = [ aws_eks_fargate_profile.coredns ]
#  triggers = {
#    // fire any time the cluster is update in a way that changes its endpoint or auth
#    endpoint = aws_eks_cluster.eks_cluster.endpoint
#    ca_crt   = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
#    token    = data.aws_eks_cluster_auth.cluster.token
#  }
#  provisioner "local-exec" {
#    command = <<EOH
#cat >/tmp/ca.crt <<EOF
#${base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)}
#EOF
#apk --no-cache add curl && \
#curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.17.9/2020-08-04/bin/linux/amd64/aws-iam-authenticator && chmod +x ./aws-iam-authenticator && \
#curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x ./kubectl && \
#mkdir -p $HOME/bin && mv ./aws-iam-authenticator $HOME/bin/ && export PATH=$PATH:$HOME/bin && \
#./kubectl \
#  --server="${aws_eks_cluster.eks_cluster.endpoint}" \
#  --certificate_authority=/tmp/ca.crt \
#  --token="${data.aws_eks_cluster_auth.cluster.token}" \
#  patch deployment coredns \
#  -n kube-system --type json \
#  -p='[{"op": "remove", "path": "/spec/template/metadata/annotations/eks.amazonaws.com~1compute-type"}]'
#EOH
#  }
#}
#resource "null_resource" "k8s_patcher" {
#  depends_on = [ aws_eks_fargate_profile.coredns ]
#  triggers = {
#    // fire any time the cluster is update in a way that changes its endpoint or auth
#    endpoint = aws_eks_cluster.eks_cluster.endpoint
#    ca_crt   = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
#    token    = data.aws_eks_cluster_auth.cluster.token
#  }
#  provisioner "local-exec" {
#    command = <<EOH
#cat >/tmp/ca.crt <<EOF
#${base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)}
#EOF
#apk --no-cache add curl && \
#curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.17.9/2020-08-04/bin/linux/amd64/aws-iam-authenticator && chmod +x ./aws-iam-authenticator && \
#curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x ./kubectl && \
#mkdir -p $HOME/bin && mv ./aws-iam-authenticator $HOME/bin/ && export PATH=$PATH:$HOME/bin && \
#./kubectl \
#  --server="${aws_eks_cluster.eks_cluster.endpoint}" \
#  --certificate_authority=/tmp/ca.crt \
#  --token="${data.aws_eks_cluster_auth.cluster.token}" \
#  patch deployment coredns \
#  -n kube-system --type json \
#  -p='[{"op": "remove", "path": "/spec/template/metadata/annotations/eks.amazonaws.com~1compute-type"}]'
#EOH
#  }
#}
resource "aws_iam_policy" "AmazonEKSClusterCloudWatchMetricsPolicy" {
  name   = "AmazonEKSClusterCloudWatchMetricsPolicy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "cloudwatch:PutMetricData"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}
EOF
}


resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.cluster_name}-cluster-role"
  description = "Allow cluster to manage node groups, fargate nodes and cloudwatch logs"
  force_detach_policies = true
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "eks.amazonaws.com",
          "eks-fargate-pods.amazonaws.com"
          ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy1" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSCloudWatchMetricsPolicy" {
  policy_arn = aws_iam_policy.AmazonEKSClusterCloudWatchMetricsPolicy.arn
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSVPCResourceController1" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_cloudwatch_log_group" "cloudwatch_log_group" {
  name              = "/aws/eks/${var.cluster_name}-${var.environment}/cluster"
  retention_in_days = 30

  tags = {
    Name        = "${var.cluster_name}-${var.environment}-eks-cloudwatch-log-group"
  }
}

resource "aws_eks_fargate_profile" "eks_fargate" {
  cluster_name           = aws_eks_cluster.eks_cluster.name
  fargate_profile_name   = "${var.cluster_name}-${var.environment}-fargate-profile"
  pod_execution_role_arn = aws_iam_role.eks_fargate_role.arn
  subnet_ids             = var.private_subnets

  selector {
    namespace = "${var.fargate_namespace}"
  }

  

  timeouts {
    create   = "30m"
    delete   = "30m"
  }
}

resource "aws_iam_role" "eks_fargate_role" {
  name = "${var.cluster_name}-fargate_cluster_role"
  description = "Allow fargate cluster to allocate resources for running pods"
  force_detach_policies = true
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "eks.amazonaws.com",
          "eks-fargate-pods.amazonaws.com"
          ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSFargatePodExecutionRolePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.eks_fargate_role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_fargate_role.name
}


resource "aws_iam_role_policy_attachment" "AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_fargate_role.name
}


#resource "aws_eks_node_group" "eks_node_group" {
#  cluster_name    = aws_eks_cluster.eks_cluster.name
#  node_group_name = "${var.cluster_name}-${var.environment}-node_group"
#  node_role_arn   = aws_iam_role.eks_node_group_role.arn
#  subnet_ids      = var.public_subnets
#
#  scaling_config {
#    desired_size = 2
#    max_size     = 3
#    min_size     = 2
#  }
#
#  instance_types  = ["${var.eks_node_group_instance_types}"]
#
#  depends_on = [
#    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
#    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
#    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
#  ]
#}
#
#resource "aws_iam_role" "eks_node_group_role" {
#  name = "${var.cluster_name}-node-group_role"
#
#  assume_role_policy = jsonencode({
#    Statement = [{
#      Action = "sts:AssumeRole"
#      Effect = "Allow"
#      Principal = {
#        Service = "ec2.amazonaws.com"
#      }
#    }]
#    Version = "2012-10-17"
#  })
#}
#
#resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
#  role       = aws_iam_role.eks_node_group_role.name
#}
#
#resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
#  role       = aws_iam_role.eks_node_group_role.name
#}
#
#resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
#  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
#  role       = aws_iam_role.eks_node_group_role.name
#}

data "tls_certificate" "auth" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "main" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.auth.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}


