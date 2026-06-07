import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import AnalyzeView from '../views/AnalyzeView.vue'
import AptView from '../views/AptView.vue'
import ScoringConfig from '../components/ScoringConfig.vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: HomeView,
  },
  {
    path: '/analyze',
    name: 'analyze',
    component: AnalyzeView,
  },
  {
    path: '/apt',
    name: 'apt-detail',
    component: AptView,
  },
   {
    path: "/settings",
    name: "settings",
    component: ScoringConfig,
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

export default router
