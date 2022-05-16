data "kubernetes_ingress" "address" {
  metadata {
    name = "owncloud-lb"
    namespace = "fargate-node"
  }
}



#output "server_dns" {
#    value = data.kubernetes_ingress.address.status[0].load_balancer[0].ingress[0].hostname
#}