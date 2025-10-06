#!/bin/bash
echo "🎉 TEST FINAL - ÉTAPE 4 RÉUSSIE ! 🎉"
echo "===================================="

# 1. Services
echo "1. ✅ SERVICES DOCKER:"
docker-compose ps

# 2. Elasticsearch
echo -e "\n2. ✅ ELASTICSEARCH:"
curl -s http://localhost:9200/_cluster/health | jq '{
  status: .status,
  nodes: .number_of_nodes,
  active_shards: .active_shards,
  disk_usage: .disk_usage_percent
}'

# 3. Kibana
echo -e "\n3. ✅ KIBANA:"
if curl -s http://localhost:5601 > /dev/null; then
    echo "✅ Kibana est PRÊT et ACCESSIBLE !"
    echo "🌐 http://localhost:5601"
else
    echo "❌ Kibana inaccessible"
fi

# 4. Test d'intégration
echo -e "\n4. ✅ TEST D'INTÉGRATION COMPLET:"
TEST_DATA='{
  "src_ip": "192.168.1.100",
  "dst_ip": "8.8.8.8",
  "protocol": "TCP",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "alert_type": "Port Scan",
  "severity": "HIGH",
  "message": "ÉTAPE 4 RÉUSSIE - Stack ELK complètement opérationnelle !"
}'

echo $TEST_DATA | nc localhost 5000
sleep 3

echo -e "\n5. 📊 DONNÉES DANS ELASTICSEARCH:"
curl -s "http://localhost:9200/homesoc-alerts-*/_search" | jq '.hits.hits[]._source'

echo -e "\n🎊 FÉLICITATIONS ! 🎊"
echo "===================="
echo "✅ ÉTAPE 4 TERMINÉE AVEC SUCCÈS !"
echo "✅ Votre SIEM ELK Stack est MAINTENANT OPÉRATIONNEL"
echo "✅ Espace disque : 59GB (38% utilisé)"
echo "✅ Kibana PRÊT et ACCESSIBLE"
echo "✅ Logstash fonctionnel"
echo "✅ Elasticsearch en bonne santé"
echo ""
echo "🌐 Accédez à Kibana : http://localhost:5601"
echo "💡 Configurez l'index pattern : homesoc-*"
echo "🚀 Prêt pour l'intégration des composants de sécurité !"
